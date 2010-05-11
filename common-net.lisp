;;;; COMMON-NET -- Abstract networking library

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package :common-net)
    (defpackage :common-net
      (:nicknames :net)
      (:use :cl))))
(in-package :common-net)

;;; General declarations

(defclass address () ())

(defclass host-address (address) ())

(defclass inet-address (address) ())

(defclass inet-host-address (inet-address host-address) ())

(defgeneric format-address (address))
(defgeneric connect-to-address (target &key local))
(defgeneric bind-to-address (address))
(defgeneric close-socket (socket))
(defgeneric socket-open-p (socket))
(defgeneric socket-local-address (socket))
(defgeneric socket-remote-address (socket))

(defclass socket () ())
(defclass listen-socket (socket) ())
(defclass stream-socket (socket) 	; Gray stream superclasses are added for implementations that support it.
  ((mode :initform :byte)
   (byte-buffer :initform (make-array '(16) :element-type '(unsigned-byte 8) :adjustable t)
		:type (array (unsigned-byte 8)))
   (byte-read-pos :initform 0 :type integer)
   (byte-write-pos :initform 0 :type integer)
   (char-buffer :initform (make-array '(16) :element-type 'character :adjustable t :fill-pointer 0)
		:type (array character))
   (char-read-pos :initform 0 :type integer)
   encoder decoder))
(defclass datagram-socket (socket) ())

(defgeneric accept (socket))
(defgeneric socket-send (socket data &key start end no-hang))
(defgeneric socket-send-to (socket data dest &key start end from no-hang))
(defgeneric socket-recv-into (socket buf &key start end no-hang))
(defgeneric socket-recv (socket &key no-hang max-len))

(defgeneric stream-socket-mode (socket))
(defgeneric stream-socket-decode-characters (socket charset))

(defmethod socket-recv ((socket socket) &key no-hang (max-len 65536))
  (let ((buf (make-array (list max-len) :element-type '(unsigned-byte 8))))
    (multiple-value-bind (len from to)
	(socket-recv-into socket buf :no-hang no-hang)
      (if (null len)
	  (values nil nil nil)
	  (values (subseq buf 0 len) from to)))))

(defmethod print-object ((address address) stream)
  (if *print-escape*
      (format stream "#<~S ~A>" (class-name (class-of address)) (format-address address))
      (princ (format-address address) stream))
  address)

(export '(address host-address inet-address inet-host-address
	  format-address
	  connect-to-address bind-to-address close-socket
	  socket-local-address socket-remote-address
	  accept socket-send socket-send-to socket-recv-into socket-recv))

(defmethod stream-socket-mode ((socket stream-socket))
  (slot-value socket 'mode))

(defmethod stream-socket-decode-characters ((socket stream-socket) charset)
  (unless (eq (stream-socket-mode socket) :byte)
    (simple-socket-error socket "~S is already in character-decoding mode." socket))
  (setf (slot-value socket 'encoder) (charcode:make-encoder charset)
	(slot-value socket 'decoder) (charcode:make-decoder charset)
	(slot-value socket 'mode) :character))

;;; Utility macros

(defmacro with-open-socket ((var socket) &body body)
  (let ((sk (gensym)))
    `(let* ((,sk ,socket)
	    (,var ,sk))
       (unwind-protect (locally ,@body)
	 (close-socket ,sk)))))

(defmacro with-connection ((var target &key local charset) &body body)
  `(with-open-socket (,var (connect-to-address ,target :local ,local))
     ,@(when charset (list `(stream-socket-decode-characters ,var ,charset)))
     ,@body))

(defmacro with-bound-socket ((var address) &body body)
  `(with-open-socket (,var (bind-to-address ,address))
     ,@body))

(export '(with-open-socket with-connection with-bound-socket))

;;; Common condition types

(define-condition socket-condition (condition)
  ((socket :initarg :socket :type socket)))

(define-condition address-busy (error)
  ((address :initarg :address :type address))
  (:report (lambda (c s)
	     (format s "The address ~A is busy." (format-address (slot-value c 'address))))))

(define-condition connection-refused (error)
  ((address :initarg :address :type address))
  (:report (lambda (c s)
	     (format s "Connection to ~A was refused by the remote host." (format-address (slot-value c 'address))))))

(define-condition socket-closed (error socket-condition) ()
  (:report (lambda (c s)
	     (format s "The socket ~S is closed." (slot-value c 'socket)))))

(define-condition socket-disconnected (socket-closed) ()
  (:report (lambda (c s)
	     (format s "The socket ~S has been closed from the other side." (slot-value c 'socket)))))

(define-condition simple-socket-error (simple-error socket-condition) ())

(defun simple-socket-error (socket format &rest args)
  (error 'simple-socket-error :socket socket :format-control format :format-arguments args))

;;; Gray stream implementation for stream sockets

(define-condition stream-mode-error (socket-condition stream-error error)
  ((expected-mode :initarg :expected-mode))
  (:report (lambda (c s)
	     (with-slots (expected-mode socket) c
	       (format s "Tried to use ~S in ~A mode, but it is in ~A mode." socket expected-mode (stream-socket-mode socket))))))

(defun gray-stream-element-type (socket)
  (declare (type stream-socket socket))
  (ecase (slot-value socket 'mode)
    ((:byte) '(unsigned-byte 8))
    ((:character) 'character)))

(defun gray-open-stream-p (socket)
  (declare (type stream-socket socket))
  (socket-open-p socket))

(defun fill-byte-buffer (socket bytes &optional no-hang)
  (declare (type stream-socket socket)
	   (type fixnum bytes))
  (with-slots (byte-buffer byte-read-pos byte-write-pos) socket
    (loop (unless (< (- byte-write-pos byte-read-pos) bytes) (return t))
       (when (< (- (length byte-buffer) byte-read-pos) bytes)
	 (adjust-array byte-buffer (list (+ byte-read-pos bytes 128))))
       (let ((recv-len (socket-recv-into socket byte-buffer :start byte-write-pos :no-hang no-hang)))
	 (cond ((null recv-len)
		(unless no-hang
		  (error "~S returned NIL even when called blocking." 'socket-recv-into))
		(return :wait))
	       ((= recv-len 0)
		(return nil)))
	 (incf byte-write-pos recv-len)))))

(defun trim-byte-buffer (socket)
  (declare (type stream-socket socket))
  (with-slots (byte-buffer byte-read-pos byte-write-pos) socket
    (replace byte-buffer byte-buffer :start2 byte-read-pos :end2 byte-write-pos)
    (decf byte-write-pos byte-read-pos)
    (setf byte-read-pos 0)
    (when (> (length byte-buffer) (* byte-write-pos 2))
      (adjust-array byte-buffer (list byte-write-pos)))))

(defun gray-stream-read-byte (socket)
  (declare (type stream-socket socket))
  (unless (fill-byte-buffer socket 1)
    (return-from gray-stream-read-byte :eof))
  (unless (eq (stream-socket-mode socket) :byte)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :byte))
  (with-slots (byte-buffer byte-read-pos) socket
    (prog1 (aref byte-buffer byte-read-pos)
      (when (> (incf byte-read-pos) 128)
	(trim-byte-buffer socket)))))

(defun gray-stream-write-byte (socket byte)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :byte)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :byte))
  (let ((buf (make-array '(1) :element-type '(unsigned-byte 8) :initial-element byte)))
    (loop (when (> (socket-send socket buf) 0)
	    (return)))))

(defun fill-char-buffer (socket chars &optional no-hang)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (with-slots (decoder byte-buffer byte-read-pos byte-write-pos char-buffer char-read-pos) socket
    (loop (unless (< (- (length char-buffer) char-read-pos) chars) (return t))
       (case (fill-byte-buffer socket chars no-hang)
	 ((nil) (return nil))
	 ((:wait) (return :wait)))
       (funcall decoder byte-buffer char-buffer :start byte-read-pos :end byte-write-pos)
       (setf byte-read-pos 0
	     byte-write-pos 0))))

(defun trim-char-buffer (socket)
  (declare (type stream-socket socket))
  (with-slots (char-buffer char-read-pos) socket
    (replace char-buffer char-buffer :start2 char-read-pos)
    (decf (fill-pointer char-buffer) char-read-pos)
    (setf char-read-pos 0)))

(defun gray-stream-read-char (socket)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (unless (fill-char-buffer socket 1)
    (return-from gray-stream-read-char :eof))
  (with-slots (char-buffer char-read-pos) socket
    (prog1 (aref char-buffer char-read-pos)
      (when (>= (incf char-read-pos) 64)
	(trim-char-buffer socket)))))

(defun gray-stream-unread-char (socket char)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (with-slots (char-buffer char-read-pos) socket
    (when (= char-read-pos 0)
      (let ((len (length char-buffer)))
	(when (< (array-dimension char-buffer 0) (+ len 16))
	  (adjust-array char-buffer (list (setf (fill-pointer char-buffer) (+ len 16)))))
	(replace char-buffer char-buffer :start1 16 :end2 len)))
    (setf (aref char-buffer (decf char-read-pos)) char)
    nil))

(defun gray-stream-read-char-no-hang (socket)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (case (fill-char-buffer socket 1)
    ((nil) (return-from gray-stream-read-char-no-hang :eof))
    ((:wait) (return-from gray-stream-read-char-no-hang nil)))
  (with-slots (char-buffer char-read-pos) socket
    (prog1 (aref char-buffer char-read-pos)
      (when (>= (incf char-read-pos) 64)
	(trim-char-buffer socket)))))

(defun gray-stream-peek-char (socket)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (unless (fill-char-buffer socket 1)
    (return-from gray-stream-peek-char :eof))
  (with-slots (char-buffer char-read-pos) socket
    (aref char-buffer char-read-pos)))

(defun gray-stream-listen (socket)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (case (fill-char-buffer socket 1)
    ((nil :wait) (return-from gray-stream-listen nil)))
  (with-slots (char-buffer char-read-pos) socket
    (aref char-buffer char-read-pos)))

(defun gray-stream-write-char (socket char)
  (declare (type stream-socket socket))
  (unless (eq (stream-socket-mode socket) :character)
    (error 'stream-mode-error :stream socket :socket socket :expected-mode :character))
  (with-slots (encoder) socket
    (let ((seq (make-array '(1) :element-type 'character :initial-element char))
	  (outbuf (make-array '(16) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
      (funcall encoder seq outbuf)
      (let ((pos 0))
	(loop (unless (< pos (length outbuf)) (return))
	   (incf pos (socket-send socket outbuf :start pos)))))))

(defun gray-stream-read-sequence (socket seq start end)
  (declare (type stream-socket socket))
  (ecase (stream-socket-mode socket)
    ((:byte)
     (fill-byte-buffer socket (- end start))
     (with-slots (byte-buffer byte-read-pos byte-write-pos) socket
       (replace seq byte-buffer :start1 start :start2 byte-read-pos :end1 end :end2 byte-write-pos)
       (let ((len (min (- end start) (- byte-write-pos byte-read-pos))))
	 (when (> (incf byte-read-pos len) 128)
	   (trim-byte-buffer socket))
	 (+ start len))))
    ((:character)
     (fill-char-buffer socket (- end start))
     (with-slots (char-buffer char-read-pos) socket
       (replace seq char-buffer :start1 start :start2 char-read-pos :end1 end :end2 (length char-buffer))
       (let ((len (min (- end start) (- (length char-buffer) char-read-pos))))
	 (when (> (incf char-read-pos len) 128)
	   (trim-char-buffer socket))
	 (+ start len))))))

(defmethod gray-stream-write-sequence (socket seq start end)
  (declare (type stream-socket socket))
  (let ((end (or end (length seq))))
    (ecase (stream-socket-mode socket)
      ((:byte)
       (loop (unless (< start end) (return seq))
	  (incf start (socket-send socket seq :start start :end end))))
      ((:character)
       (with-slots (encoder) socket
	 (let ((outbuf (make-array (list (- end start)) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
	       (pos 0))
	   (funcall encoder seq outbuf :start start :end end)
	   (loop (unless (< pos (length outbuf)) (return seq))
	      (incf pos (socket-send socket outbuf :start pos)))))))))

;;; IPv4 addresses

(defclass ipv4-address (inet-host-address)
  ((bytes :initarg :bytes :type (array (unsigned-byte 8) 4))))

(defun make-ipv4-address (o1 o2 o3 o4)
  (make-instance 'ipv4-address :bytes (make-array '(4)
						  :element-type '(unsigned-byte 8)
						  :initial-contents (list o1 o2 o3 o4))))

(defun parse-ipv4-address (string)
  (let ((o 0)
	(start 0)
	(string (concatenate 'string string "."))
	(buf (make-array '(4) :element-type '(unsigned-byte 8))))
    (dotimes (i (length string))
      (let ((ch (elt string i)))
	(cond ((eql ch #\.)
	       (if (< o 4)
		   (progn (setf (aref buf o) (let ((n (parse-integer string :start start :end i)))
					       (if (and n (<= 0 n 255))
						   n
						   (error "IPv4 dottet-quad numbers must be octets"))))
			  (setf start (1+ i))
			  (incf o))
		   (error "Too many octets in IPv4 address")))
	      ((char<= #\0 ch #\9)
	       nil)
	      (t (error "Invalid character ~S in IPv4 address" ch)))))
    (if (< o 4)
	(error "Too few octets in IPv4 address")
	(make-instance 'ipv4-address :bytes buf))))

(defmethod format-address ((address ipv4-address))
  (with-slots (bytes) address
    (format nil "~D.~D.~D.~D"
	    (aref bytes 0)
	    (aref bytes 1)
	    (aref bytes 2)
	    (aref bytes 3))))

(export '(ipv4-address make-ipv4-address parse-ipv4-address))

;;; IPv6 addresses

(defclass ipv6-address (inet-host-address)
  ((bytes :initarg :bytes :type (array (unsigned-byte 8) 16))))

(defun parse-ipv6-address (string)
  (declare (ignore string))
  (error "IPv6 parsing not implemented yet"))

(export '(ipv6-address parse-ipv6-address))

;;; TCP code

(defclass inet-port-address (inet-address)
  ((host :initarg :host :type (or null inet-host-address))
   (port :initarg :port :type (unsigned-byte 16))))

(defclass tcp-address (inet-port-address) ())

(defmethod format-address ((address tcp-address))
  (with-slots (host port) address
    (format nil "~A:~D" (if host (format-address host) "*") port)))

(defun inet-resolve-colon-port (string)
  (let ((colon (position #\: string)))
    (if (null colon)
	(error "No colon in TCP address"))
    (if (find #\: string :start (1+ colon))
	(error "More than one colon in TCP address"))
    (let ((port (parse-integer (subseq string (1+ colon))))
	  (host (let ((host-part (subseq string 0 colon)))
		  (if (equal host-part "*")
		      nil
		      (resolve-address host-part)))))
      (if (not (typep host '(or null inet-host-address)))
	  (error "Must have an internet address for TCP connections"))
      (values host port))))

(defun resolve-tcp-colon-port (address)
  (multiple-value-bind (host port)
      (inet-resolve-colon-port address)
    (make-instance 'tcp-address :host host :port port)))

(export '(tcp-address resolve-tcp-colon-port))

;;; UDP code

(defclass udp-address (inet-port-address) ())

(defmethod format-address ((address udp-address))
  (with-slots (host port) address
    (format nil "~A:~D" (if host (format-address host) "*") port)))

(defun resolve-udp-colon-port (address)
  (multiple-value-bind (host port)
      (inet-resolve-colon-port address)
    (make-instance 'udp-address :host host :port port)))

(export '(udp-address resolve-udp-colon-port))

;;; Unix sockets

(defclass local-address (address)
  ((path :initarg :path :type pathname)))

(defmethod format-address ((address local-address))
  (namestring (slot-value address 'path)))

(defclass local-stream-address (local-address) ())
(defclass local-seq-address (local-address) ())
(defclass local-datagram-address (local-address) ())

(defun make-local-address (pathspec &optional (type :stream))
  (make-instance (ecase type
		   ((:stream) 'local-stream-address)
		   ((:seq) 'local-seq-address)
		   ((:datagram) 'local-datagram-address))
		 :path (pathname pathspec)))

(export '(local-address make-local-address))
