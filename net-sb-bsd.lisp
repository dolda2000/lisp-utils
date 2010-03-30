(in-package :common-net)

(defclass sbcl-socket (socket)
  ((sb-socket :initarg :sb-socket :type sb-bsd-sockets:socket)))
(defclass sbcl-listen-socket (listen-socket sbcl-socket) ())
(defclass sbcl-stream-socket (stream-socket sbcl-socket) ())
(defclass sbcl-datagram-socket (datagram-socket sbcl-socket) ())

(defmacro with-sb-socket ((var socket) &body body)
  (let ((success (gensym "SUCCESS")))
    `(let ((,var ,socket)
	   (,success nil))
       (unwind-protect
	    (multiple-value-prog1
		(progn ,@body)
	      (setf ,success t))
	 (unless ,success
	   (sb-bsd-sockets:socket-close ,var))))))

(defun map-sbcl-to-address (sk address)
  (etypecase sk
    (sb-bsd-sockets:inet-socket
     (let ((host (first address))
	   (port (second address)))
       (make-instance (ecase (sb-bsd-sockets:socket-type sk)
			((:stream) 'tcp-address)
			((:datagram) 'udp-address))
		      :host (if (every #'zerop host)
				nil
				(make-instance 'ipv4-address :bytes host))
		      :port port)))))

(defun map-address-to-sbcl (sk address)
  (etypecase sk
    (sb-bsd-sockets:inet-socket
     (etypecase address
       (inet-port-address
	(with-slots (host port) address
	  (list (etypecase host
		  (null #(0 0 0 0))
		  (ipv4-address (slot-value host 'bytes)))
		port)))))
    (sb-bsd-sockets:local-socket
     (etypecase address
       (local-address
	(namestring (slot-value address 'path)))))))

(defun sbcl-socket-type-and-args (address)
  (etypecase address
    (inet-port-address
     (let ((type (etypecase address
		   (tcp-address :stream)
		   (udp-address :datagram))))
       (with-slots (host port) address
	 (etypecase host
	   (null
	    ;; This should probably be changed to use IPv6 when SBCL
	    ;; supports it. At least on Linux, since it supports
	    ;; v4-mapping, but it is less clear what to do on the
	    ;; BSDs.
	    (list 'sb-bsd-sockets:inet-socket :type type))
	   (ipv4-address
	    (list 'sb-bsd-sockets:inet-socket :type type))
	   (ipv6-address
	    (error "SBCL does not support IPv6."))))))
    (inet-host-address
     (error "SBCL does not support raw sockets."))
    (local-stream-address
     (list 'sb-bsd-sockets:local-socket :type :stream))
    (local-seq-address
     (error "SBCL does not support Unix seqpacket sockets."))
    (local-datagram-address
     (list 'sb-bsd-sockets:local-socket :type :datagram))))

(defun sb-bsd-socket-for-address (address)
  (apply #'make-instance (sbcl-socket-type-and-args address)))

(defun check-not-closed (socket)
  (declare (type sbcl-socket socket))
  (when (null (slot-value socket 'sb-socket))
    (error 'socket-closed :socket socket)))

(define-condition wrapped-socket-error (error socket-condition)
  ((cause :initarg :cause))
  (:report (lambda (c s)
	     (princ (slot-value c 'cause) s))))

(defun map-sb-bsd-error (socket c)
  (cond ((eql (sb-bsd-sockets::socket-error-errno c) 32)  ; EPIPE
	 (error 'socket-disconnected :socket socket))
	((eql (sb-bsd-sockets::socket-error-errno c) 104) ; ECONNRESET
	 (error 'socket-disconnected :socket socket))
	(t (error 'wrapped-socket-error :socket socket :cause c))))

(defmacro map-sb-bsd-errors ((socket) &body body)
  (let ((c (gensym "C")))
    `(handler-bind ((sb-bsd-sockets:socket-error (lambda (,c) (map-sb-bsd-error ,socket ,c))))
       ,@body)))

(defmacro retry-loop ((format-string &rest format-args) &body body)
  `(loop (with-simple-restart (retry ,format-string ,@format-args)
	   (return ,@body))))

(defmethod close-socket ((socket sbcl-socket))
  (with-slots (sb-socket) socket
    (unless (null sb-socket)
      (sb-bsd-sockets:socket-close sb-socket)
      (setf sb-socket nil))))

(defmethod socket-open-p ((socket sbcl-socket))
  (if (slot-value socket 'sb-socket) t nil))

(defmethod socket-local-address ((socket sbcl-socket))
  (check-not-closed socket)
  (with-slots (sb-socket) socket
    (map-sbcl-to-address sb-socket (multiple-value-list (sb-bsd-sockets:socket-name sb-socket)))))

(defmethod socket-remote-address ((socket sbcl-socket))
  (check-not-closed socket)
  (with-slots (sb-socket) socket
    (map-sbcl-to-address sb-socket (multiple-value-list (sb-bsd-sockets:socket-peername sb-socket)))))

(defmethod socket-send ((socket sbcl-socket) buf &key (start 0) (end (length buf)) no-hang)
  (check-not-closed socket)
  (let ((result (map-sb-bsd-errors (socket)
		  (retry-loop ("Retry the send operation.")
		    (sb-bsd-sockets:socket-send (slot-value socket 'sb-socket)
						(if (= start 0)
						    buf
						    (subseq buf start end))
						(- end start)
						:nosignal t
						:dontwait no-hang)))))
    (etypecase result
      (null 0)
      (integer result))))

(defmethod socket-send-to ((socket sbcl-socket) buf destination &key (start 0) (end (length buf)) from no-hang)
  (check-not-closed socket)
  (when from
    (error "SB-BSD-THREADS does not support specifying the source address of individual packets."))
  (let ((result (map-sb-bsd-errors (socket)
		  (retry-loop ("Retry the send operation.")
		    (sb-bsd-sockets:socket-send (slot-value socket 'sb-socket)
						(if (= start 0)
						    buf
						    (subseq buf start end))
						(- end start)
						:address (map-address-to-sbcl socket destination)
						:nosignal t
						:dontwait no-hang)))))
    (etypecase result
      (null 0)
      (integer result))))

(defmethod socket-recv-into ((socket sbcl-socket) buf &key (start 0) (end (length buf)) no-hang)
  (check-not-closed socket)
  (check-type buf sequence)
  (let* ((direct (and (= start 0) (typep buf '(array (unsigned-byte 8)))))
	 (readbuf (if direct
		      buf
		      (make-array (list (- end start)) :element-type '(unsigned-byte 8))))
	 (ret-list (multiple-value-list
		    (map-sb-bsd-errors (socket)
		      (retry-loop ("Try receiving again.")
			(sb-bsd-sockets:socket-receive (slot-value socket 'sb-socket)
								  readbuf
								  (- end start)
								  :dontwait no-hang
								  :element-type '(unsigned-byte 8))))))
	 (len (second ret-list))
	 (addr-list (cddr ret-list)))
    (etypecase len
      (null (values nil nil))
      (integer
       (unless direct
	 (replace buf readbuf :start1 start :end2 len))
       (values len (map-sbcl-to-address (slot-value socket 'sb-socket) addr-list))))))

(defmethod bind-to-address ((address tcp-address))
  (make-instance 'sbcl-listen-socket
		 :sb-socket (with-sb-socket (sk (sb-bsd-socket-for-address address))
			      (handler-bind
				  ((sb-bsd-sockets:address-in-use-error (lambda (c)
									  (declare (ignore c))
									  (error 'address-busy :address address))))
				(retry-loop ("Try binding again.")
				  (apply #'sb-bsd-sockets:socket-bind sk (map-address-to-sbcl sk address))))
			      (sb-bsd-sockets:socket-listen sk 64)
			      sk)))

(defmethod connect-to-address ((remote tcp-address) &key local)
  (typecase local
    (string (setf local (resolve-address local))))
  (make-instance 'sbcl-stream-socket
		 :sb-socket (with-sb-socket (sk (sb-bsd-socket-for-address (if local local remote)))
			      (if local
				  (handler-case
				      (apply #'sb-bsd-sockets:socket-bind sk (map-address-to-sbcl sk local))
				    (sb-bsd-sockets:address-in-use-error ()
				      (error 'address-busy :address local))))
			      (retry-loop ("Retry connection.")
				(handler-bind
				    ((sb-bsd-sockets:connection-refused-error (lambda (c)
										(declare (ignore c))
										(error 'connection-refused :address remote))))
				  (apply #'sb-bsd-sockets:socket-connect sk (map-address-to-sbcl sk remote))))
			      sk)))

(defmethod bind-to-address ((address udp-address))
  (make-instance 'sbcl-datagram-socket
		 :sb-socket (with-sb-socket (sk (sb-bsd-socket-for-address address))
			      (handler-case
				  (apply #'sb-bsd-sockets:socket-bind sk (map-address-to-sbcl sk address))
				(sb-bsd-sockets:address-in-use-error ()
				  (error 'address-busy :address address)))
			      sk)))

(defmethod connect-to-address ((remote udp-address) &key local)
  (typecase local
    (string (setf local (resolve-address local))))
  (make-instance 'sbcl-datagram-socket
		 :sb-socket (with-sb-socket (sk (sb-bsd-socket-for-address (if local local remote)))
			      (if local
				  (handler-case
				      (apply #'sb-bsd-sockets:socket-bind sk (map-address-to-sbcl sk local))
				    (sb-bsd-sockets:address-in-use-error ()
				      (error 'address-busy :address local))))
			      (apply #'sb-bsd-sockets:socket-connect sk (map-address-to-sbcl sk remote))
			      sk)))

(defmethod accept ((socket sbcl-listen-socket))
  (check-not-closed socket)
  (let* ((ret-list (multiple-value-list (sb-bsd-sockets:socket-accept (slot-value socket 'sb-socket))))
	 (sk (first ret-list))
	 (addr-list (rest ret-list)))
    (with-sb-socket (sk sk)
      (values (make-instance 'sbcl-stream-socket :sb-socket sk)
	      (map-sbcl-to-address sk addr-list)))))
