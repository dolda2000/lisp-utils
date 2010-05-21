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
			((:stream) 'tcp4-address)
			((:datagram) 'udp4-address))
		      :host-bytes host
		      :port port)))
    (sb-bsd-sockets:local-socket
     (make-instance (ecase (sb-bsd-sockets:socket-type sk)
		      ((:stream) 'local-stream-address)
		      ((:datagram 'local-datagram-address)))
		    :path (first address)))))

(defun map-address-to-sbcl (sk address)
  (etypecase sk
    (sb-bsd-sockets:inet-socket
     (etypecase address
       ((and ipv4-address inet-port-address)
	(with-slots (host-bytes port) address
	  (list host-bytes port)))))
    (sb-bsd-sockets:local-socket
     (etypecase address
       (local-address
	(list (namestring (slot-value address 'path))))))))

(defun sbcl-socket-type-and-args (address)
  (etypecase address
    (tcp4-address
     '(sb-bsd-sockets:inet-socket :type :stream))
    (udp4-address
     '(sb-bsd-sockets:inet-socket :type :datagram))
    (ipv6-address
     (simple-network-error "SBCL does not support IPv6."))
    (inet-host-address
     (simple-network-error "SBCL does not support raw sockets."))
    (local-stream-address
     '(sb-bsd-sockets:local-socket :type :stream))
    (local-seq-address
     (simple-network-error "SBCL does not support Unix seqpacket sockets."))
    (local-datagram-address
     '(sb-bsd-sockets:local-socket :type :datagram))))

(defun sb-bsd-socket-for-address (address)
  (apply #'make-instance (sbcl-socket-type-and-args address)))

(defun check-not-closed (socket)
  (declare (type sbcl-socket socket))
  (when (null (slot-value socket 'sb-socket))
    (error 'socket-closed :socket socket)))

(defgeneric socket-class-for-address (address mode))
(defmethod socket-class-for-address ((address tcp-address) (mode (eql :connect))) 'sbcl-stream-socket)
(defmethod socket-class-for-address ((address tcp-address) (mode (eql :bind))) 'sbcl-listen-socket)
(defmethod socket-class-for-address ((address udp-address) mode) 'sbcl-datagram-socket)
(defmethod socket-class-for-address ((address inet-host-address) mode) 'sbcl-datagram-socket)
(defmethod socket-class-for-address ((address local-stream-address) mode) 'sbcl-stream-socket)
(defmethod socket-class-for-address ((address local-seq-address) mode) 'sbcl-datagram-socket)
(defmethod socket-class-for-address ((address local-datagram-address) mode) 'sbcl-datagram-socket)

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
  `(loop (with-simple-restart (:retry ,format-string ,@format-args)
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
    (simple-network-error "SB-BSD-THREADS does not support specifying the source address of individual packets."))
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

(defmethod bind-to-address ((address address))
  (make-instance (socket-class-for-address address :bind)
		 :sb-socket (with-sb-socket (sk (sb-bsd-socket-for-address address))
			      (handler-bind
				  ((sb-bsd-sockets:address-in-use-error (lambda (c)
									  (declare (ignore c))
									  (error 'address-busy :address address))))
				(retry-loop ("Try binding again.")
				  (apply #'sb-bsd-sockets:socket-bind sk (map-address-to-sbcl sk address))))
			      (when (connected-address-p address)
				(sb-bsd-sockets:socket-listen sk 64))
			      sk)))

(defmethod connect-to-address ((remote address) &key local)
  (make-instance (socket-class-for-address remote :connect)
		 :sb-socket (with-sb-socket (sk (sb-bsd-socket-for-address (if local local remote)))
			      (when local
				(handler-bind
				    ((sb-bsd-sockets:address-in-use-error (lambda (c)
									    (declare (ignore c))
									    (error 'address-busy :address local))))
				  (retry-loop ("Try binding again.")
				    (apply #'sb-bsd-sockets:socket-bind sk (map-address-to-sbcl sk local)))))
			      (handler-bind
				  ((sb-bsd-sockets:connection-refused-error (lambda (c)
									      (declare (ignore c))
									      (error 'connection-refused :address remote))))
				(retry-loop ("Retry connection.")
				  (apply #'sb-bsd-sockets:socket-connect sk (map-address-to-sbcl sk remote))))
			      sk)))

(defmethod accept ((socket sbcl-listen-socket))
  (check-not-closed socket)
  (let* ((ret-list (multiple-value-list (sb-bsd-sockets:socket-accept (slot-value socket 'sb-socket))))
	 (sk (first ret-list))
	 (addr-list (rest ret-list)))
    (with-sb-socket (sk sk)
      (values (make-instance 'sbcl-stream-socket :sb-socket sk)
	      (map-sbcl-to-address sk addr-list)))))
