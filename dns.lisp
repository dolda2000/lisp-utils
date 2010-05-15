;;;; DNS implementation for COMMON-NET

(in-package :common-net)

(defstruct dns-packet
  (txid (random 65536) :type (unsigned-byte 16))
  (is-response nil)
  (opcode :query :type (member :query :iquery :status))
  (authoritative nil)
  (truncated nil)
  (recurse nil)
  (will-recurse nil)
  (resp-code :success :type (member :success :format-error :server-failure :name-error :not-implemented :refused))
  (queries '() :type list)
  (answers '() :type list)
  (authority '() :type list)
  (additional '() :type list))

(defclass resource-query ()
  ((name :initarg :name)
   (type :initarg :type)))

(defclass resource-record ()
  ((name :initarg :name)
   (ttl :initarg :ttl)))

(defvar *rr-coding-types* '())

(defmacro define-rr-type (name class type slots)
  (let ((format (mapcar #'(lambda (slot)
			    (list* (if (listp (car slot))
				      (caar slot)
				      (car slot))
				   (cdr slot)))
			slots))
	(slot-desc (mapcar #'car slots)))
    `(progn
       (defclass ,name (resource-record) ,slot-desc)
       (setf *rr-coding-types* (cons '(,name (,class ,type) ,format)
				     (remove ',name *rr-coding-types* :key #'car))))))

(define-rr-type a-record #x1 #x1
		((address ipv4-address)))
(define-rr-type ns-record #x1 #x2
		((ns-name domain-name)))
(define-rr-type cname-record #x1 #x5
		((cname domain-name)))
(define-rr-type soa-record #x1 #x6
		((mname domain-name)
		 (rname domain-name)
		 (serial uint-32)
		 (refresh uint-32)
		 (retry uint-32)
		 (expire uint-32)))
(define-rr-type ptr-record #x1 #xc
		((pointed domain-name)))
(define-rr-type mx-record #x1 #xf
		((prio uint-16)
		 (mail-host domain-name)))
(define-rr-type txt-record #x1 #x10
		((text text)))
(define-rr-type aaaa-record #x1 #x1c
		((address ipv6-address)))
(define-rr-type srv-record #x1 #x21
		((prio uint-16)
		 (weigth uint-16)
		 (port uint-16)
		 (host-name domain-name)))

;;; Packet decoding logic

(defstruct dns-decode-state
  (packet nil :type (array (unsigned-byte 8)))
  (pos 0 :type (mod 65536))
  (prev-names '() :type list))

(define-condition dns-error (error) ())
(define-condition dns-decode-error (dns-error)
  ((packet :initarg :packet)))
(define-condition simple-dns-decode-error (dns-decode-error simple-error) ())

(defun simple-dns-decode-error (packet format &rest args)
  (error 'simple-dns-decode-error :packet packet :format-control format :format-argument args))

(defun decode-uint-8 (buf)
 (declare (type dns-decode-state buf))
  (with-slots (packet pos) buf
    (when (< (- (length packet) pos) 1)
      (simple-dns-decode-error buf "DNS packet is too short (wanted a 8-bit number)."))
    (prog1 (aref packet pos)
      (incf pos))))

(defun decode-uint-16 (buf)
  (declare (type dns-decode-state buf))
  (with-slots (packet pos) buf
    (when (< (- (length packet) pos) 2)
      (simple-dns-decode-error buf "DNS packet is too short (wanted a 16-bit number)."))
    (prog1
	(+ (* (aref packet pos) 256)
	   (aref packet (1+ pos)))
      (incf pos 2))))

(defun decode-uint-32 (buf)
  (declare (type dns-decode-state buf))
  (with-slots (packet pos) buf
    (when (< (- (length packet) pos) 4)
      (simple-dns-decode-error buf "DNS packet is too short (wanted a 32-bit number)."))
    (prog1
	(+ (* (aref packet pos) #x1000000)
	   (* (aref packet (+ pos 1)) #x10000)
	   (* (aref packet (+ pos 2)) #x100)
	   (aref packet (+ pos 3)))
      (incf pos 4))))

(defun decode-domain-name (buf)
  (declare (type dns-decode-state buf))
  (labels ((decode-label ()
	     (let* ((orig-off (dns-decode-state-pos buf))
		    (len (decode-uint-8 buf)))
	       (case (ldb (byte 2 6) len)
		 ((0)
		  (if (zerop len)
		      '()
		      (with-slots (packet pos) buf
			(let* ((label (prog1
					  (handler-bind
					      ((charcode:coding-error
						(lambda (c)
						  (declare (ignore c))
						  (simple-dns-decode-error buf "DNS label was not ASCII."))))
					    (charcode:decode-string (subseq packet
									    pos (+ pos len))
								    :ascii))
					(incf pos len)))
			       (decoded (append (list label) (decode-label))))
			  (push (cons orig-off decoded) (slot-value buf 'prev-names))
			  decoded))))
		 ((3) (let* ((offset (+ (* 256 (ldb (byte 0 6) len))
					(decode-uint-8 buf)))
			     (prev (assoc offset (dns-decode-state-prev-names buf))))
			(unless prev
			  (simple-dns-decode-error buf "Domain name label pointed to non-label position."))
			(cdr prev)))
		 (t (simple-dns-decode-error buf "Illegal DNS label flags: ~D" (ldb (byte 2 6) len)))))))
    (decode-label)))

(defun decode-dns-query (buf)
  (declare (type dns-decode-state buf))
  (let* ((name (decode-domain-name buf))
	 (type (decode-uint-16 buf))
	 (class (decode-uint-16 buf))
	 (desc (find (list class type) *rr-coding-types* :key 'second :test 'equal)))
    (if desc
	(make-instance 'resource-query :name name :type (first desc))
	(progn (warn "Unknown DNS RR type: ~D, ~D" class type)
	       nil))))

(defun decode-dns-record (buf)
  (declare (type dns-decode-state buf))
  (let* ((name (decode-domain-name buf))
	 (type (decode-uint-16 buf))
	 (class (decode-uint-16 buf))
	 (ttl (decode-uint-32 buf))
	 (dlen (decode-uint-16 buf))
	 (desc (find (list class type) *rr-coding-types* :key 'second :test 'equal)))
    (when (< (length (dns-decode-state-packet buf))
	     (+ (dns-decode-state-pos buf) dlen))
      (simple-dns-decode-error buf "Not enough data left in DNS packet to decode indicated RR data length."))
    (if desc
	(let ((orig-off (dns-decode-state-pos buf))
	      (rr (make-instance (first desc)
				 :name name
				 :ttl ttl)))
	  (dolist (slot-desc (third desc))
	    (destructuring-bind (slot-name type) slot-desc
	      (setf (slot-value rr slot-name)
		    (with-slots (packet pos) buf
		      (ecase type
			((uint-16) (decode-uint-16 buf))
			((uint-32) (decode-uint-32 buf))
			((domain-name) (decode-domain-name buf))
			((text)
			 (let ((len (decode-uint-8 buf)))
			   (prog1 (subseq packet pos (+ pos len))
			     (incf pos len))))
			((ipv4-address)
			 (prog1 (make-instance 'ipv4-host-address :host-bytes (subseq packet pos (+ pos 4)))
			   (incf pos 4)))
			((ipv6-address)
			 (prog1 (make-instance 'ipv6-host-address :host-bytes (subseq packet pos (+ pos 16)))
			   (incf pos 16))))))))
	  (unless (= (dns-decode-state-pos buf) (+ orig-off dlen))
	    (simple-dns-decode-error buf "DNS RR data length did not match up with actual decoded data."))
	  rr)
	(progn (warn "Unknown DNS RR type: ~D, ~D" class type)
	       (incf (dns-decode-state-pos buf) dlen)
	       nil))))

(defun decode-dns-packet (buf)
  (declare (type dns-decode-state buf))
  (let* ((txid (decode-uint-16 buf))
	 (flags (decode-uint-16 buf))
	 (qnum (decode-uint-16 buf))
	 (ansnum (decode-uint-16 buf))
	 (autnum (decode-uint-16 buf))
	 (auxnum (decode-uint-16 buf))
	 (packet (make-dns-packet :txid txid
				  :is-response (ldb-test (byte 1 15) flags)
				  :opcode (case (ldb (byte 4 11) flags)
					    ((0) :query)
					    ((1) :iquery)
					    ((2) :status)
					    (t (simple-dns-decode-error buf "Unknown DNS opcode: ~D" (ldb (byte 4 11) flags))))
				  :authoritative (ldb-test (byte 1 10) flags)
				  :truncated (ldb-test (byte 1 9) flags)
				  :recurse (ldb-test (byte 1 8) flags)
				  :will-recurse (ldb-test (byte 1 7) flags)
				  :resp-code (case (ldb (byte 4 0) flags)
					       ((0) :success)
					       ((1) :format-error)
					       ((2) :server-failure)
					       ((3) :name-error)
					       ((4) :not-implemented)
					       ((5) :refused)
					       (t (simple-dns-decode-error buf "Unknown DNS response code: ~D" (ldb (byte 4 0) flags)))))))
    (with-slots (queries answers authority additional) packet
	(dotimes (i qnum)
	  (setf queries (append queries (list (decode-dns-query buf)))))
	(dotimes (i ansnum)
	  (setf answers (append answers (list (decode-dns-record buf)))))
	(dotimes (i autnum)
	  (setf authority (append authority (list (decode-dns-record buf)))))
	(dotimes (i auxnum)
	  (setf additional (append additional (list (decode-dns-record buf))))))
    packet))

(defun dns-decode (packet)
  (decode-dns-packet (make-dns-decode-state :packet packet)))

;;; Packet encoding logic

(defstruct dns-encode-state
  (packet-buf (make-array '(512) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0) :type (array (unsigned-byte 8)))
  (prev-names '() :type list))

(defun encode-uint-8 (buf num)
  (declare (type dns-encode-state buf)
	   (type (unsigned-byte 8) num))
  (with-slots (packet-buf) buf
    (vector-push-extend num packet-buf)))

(defun encode-uint-16 (buf num)
  (declare (type dns-encode-state buf)
	   (type (unsigned-byte 16) num))
  (with-slots (packet-buf) buf
    (vector-push-extend (ldb (byte 8 8) num) packet-buf)
    (vector-push-extend (ldb (byte 8 0) num) packet-buf)))

(defun encode-uint-32 (buf num)
  (declare (type dns-encode-state buf)
	   (type (unsigned-byte 32) num))
  (with-slots (packet-buf) buf
    (vector-push-extend (ldb (byte 8 24) num) packet-buf)
    (vector-push-extend (ldb (byte 8 16) num) packet-buf)
    (vector-push-extend (ldb (byte 8 8) num) packet-buf)
    (vector-push-extend (ldb (byte 8 0) num) packet-buf)))

(defun encode-bytes (buf bytes)
  (declare (type dns-encode-state buf)
	   (type (array (unsigned-byte 8)) bytes))
  (with-slots (packet-buf) buf
    (dotimes (i (length bytes) (values))
      (vector-push-extend (elt bytes i) packet-buf))))

(defun encode-domain-name (buf name)
  (declare (type dns-encode-state buf)
	   (type list name))
  (with-slots (packet-buf prev-names) buf
    (labels ((encode-label (name)
	       (let ((prev (find name prev-names :key 'first :test 'equal)))
		 (cond ((null name)
			(encode-uint-8 buf 0))
		       (prev
			(encode-uint-16 buf (+ #xc000 (cdr prev))))
		       (t
			(when (< (length packet-buf) 16384)
			  (push (cons name (length packet-buf)) prev-names))
			(let ((encoded (charcode:encode-string (car name) :ascii)))
			  (unless (< (length encoded) 64)
			    (error "DNS labels cannot exceed 63 octets in length: ~S" (car name)))
			  (encode-uint-8 buf (length encoded))
			  (encode-bytes buf encoded))
			(encode-label (cdr name)))))))
      (encode-label name))))

(defun encode-dns-query (buf query)
  (declare (type dns-encode-state buf)
	   (type resource-query query))
  (let ((desc (find (slot-value query 'type) *rr-coding-types* :key 'first)))
    (encode-domain-name buf (slot-value query 'name))
    (encode-uint-16 buf (second (second desc)))
    (encode-uint-16 buf (first (second desc)))))

(defun encode-dns-record (buf record)
  (declare (type dns-encode-state buf)
	   (type resource-record record))
  (let ((desc (find (class-name (class-of record)) *rr-coding-types* :key 'first)))
    (encode-domain-name buf (slot-value record 'name))
    (encode-uint-16 buf (second (second desc)))
    (encode-uint-16 buf (first (second desc)))
    (encode-uint-32 buf (slot-value record 'ttl))
    (with-slots (packet-buf) buf
      (let ((orig-off (length packet-buf)))
	(encode-uint-16 buf 0)
	(dolist (slot-desc (third desc))
	  (destructuring-bind (slot-name type) slot-desc
	    (let ((val (slot-value record slot-name)))
	      (ecase type
		((uint-16) (encode-uint-16 buf val))
		((uint-32) (encode-uint-32 buf val))
		((domain-name) (encode-domain-name buf val))
		((text) (let ((data (etypecase val
				      (string (charcode:encode-string val :ascii))
				      ((array (unsigned-byte 8)) val))))
			  (unless (< (length data) 256)
			    (error "DNS text data length cannot exceed 255 octets."))
			  (encode-uint-8 buf (length data))
			  (encode-bytes buf data)))
		((ipv4-address)
		 (check-type val ipv4-host-address)
		 (encode-bytes buf (slot-value val 'host-bytes)))
		((ipv6-address)
		 (check-type val ipv6-host-address)
		 (encode-bytes buf (slot-value val 'host-bytes)))))))
	(let ((dlen (- (length packet-buf) orig-off)))
	  (setf (aref packet-buf orig-off) (ldb (byte 8 8) dlen)
		(aref packet-buf (1+ orig-off)) (ldb (byte 8 0) dlen)))))))

(defun encode-dns-packet (buf packet)
  (declare (type dns-encode-state buf)
	   (type dns-packet packet))
  (with-slots (txid is-response opcode authoritative truncated
		    recurse will-recurse resp-code
		    queries answers authority additional) packet
    (encode-uint-16 buf txid)
    (let ((flags 0))
      (setf (ldb (byte 1 15) flags) (if is-response 1 0)
	    (ldb (byte 4 11) flags) (ecase opcode
				      ((:query) 0)
				      ((:iquery) 1)
				      ((:status) 2))
	    (ldb (byte 1 10) flags) (if authoritative 1 0)
	    (ldb (byte 1 9) flags) (if truncated 1 0)
	    (ldb (byte 1 8) flags) (if recurse 1 0)
	    (ldb (byte 1 7) flags) (if will-recurse 1 0)
	    (ldb (byte 4 0) flags) (ecase resp-code
				     ((:success) 0)
				     ((:format-error) 1)
				     ((:server-failure) 2)
				     ((:name-error) 3)
				     ((:not-implemented) 4)
				     ((:refused) 5)))
      (encode-uint-16 buf flags))
    (encode-uint-16 buf (length queries))
    (encode-uint-16 buf (length answers))
    (encode-uint-16 buf (length authority))
    (encode-uint-16 buf (length additional))
    (dolist (query queries)
      (encode-dns-query buf query))
    (dolist (rr answers)
      (encode-dns-record buf rr))
    (dolist (rr authority)
      (encode-dns-record buf rr))
    (dolist (rr additional)
      (encode-dns-record buf rr)))
  (values))

(defun dns-encode (packet)
  (check-type packet dns-packet)
  (let ((buf (make-dns-encode-state)))
    (encode-dns-packet buf packet)
    (slot-value buf 'packet-buf)))
