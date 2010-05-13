(in-package :common-net)

(require :gray-streams)

;;; Gray stream methods

;; Redefine stream-socket with Gray superclasses. I know it's ugly,
;; but I just don't know of a better way to do it.
(defclass stream-socket (socket gray-streams:fundamental-character-input-stream gray-streams:fundamental-character-output-stream
				gray-streams:fundamental-binary-input-stream gray-streams:fundamental-binary-output-stream)
  ((mode :initform :byte)
   (byte-buffer :initform (make-array '(16) :element-type '(unsigned-byte 8) :adjustable t)
		:type (array (unsigned-byte 8)))
   (byte-read-pos :initform 0 :type integer)
   (byte-write-pos :initform 0 :type integer)
   (char-buffer :initform (make-array '(16) :element-type 'character :adjustable t :fill-pointer 0)
		:type (array character))
   (char-read-pos :initform 0 :type integer)
   encoder decoder))

(macrolet ((simple (name)
	     `(defmethod
		  ,(intern (symbol-name name) (find-package :gray-streams)) ((socket stream-socket))
		(,(intern (concatenate 'string "GRAY-" (symbol-name name)) (symbol-package 'stream-socket)) socket)))
	   (simple-null (name)
	     `(defmethod
		  ,(intern (symbol-name name) (find-package :gray-streams)) ((socket stream-socket))
		nil)))
  (simple stream-element-type)
  (simple open-stream-p)
  (simple stream-read-byte)
  (simple stream-read-char)
  (simple stream-read-char-no-hang)
  (simple stream-peek-char)
  (simple stream-listen)
  (simple-null stream-line-column)
  (simple-null stream-finish-output)
  (simple-null stream-force-output)
  (simple-null stream-clear-output))

(defmethod gray-streams:stream-write-byte ((socket stream-socket) byte)
  (gray-stream-write-char socket byte))

(defmethod gray-streams:stream-unread-char ((socket stream-socket) char)
  (gray-stream-unread-char socket char))

(defmethod gray-streams:stream-write-char ((socket stream-socket) char)
  (gray-stream-write-char socket char))

(defmethod gray-streams:stream-close ((socket stream-socket) &key abort)
  (declare (ignore abort))
  (prog1
      (call-next-method)
    (close-socket socket)))

(defmethod gray-streams:stream-start-line-p ((socket stream-socket))
  (eql (gray-streams:stream-line-column socket) 0))

(defmethod gray-streams:stream-fresh-line ((socket stream-socket))
  (unless (gray-streams:stream-start-line-p socket)
    (gray-streams:stream-terpri socket)
    t))

(defmethod gray-streams:stream-write-string ((socket stream-socket) string &optional (start 0) (end (length string)))
  (gray-streams:stream-write-sequence socket string start end))

(defmethod gray-streams:stream-terpri ((socket stream-socket))
  (gray-streams:stream-write-char socket #\newline))

(defmethod gray-streams:stream-read-sequence ((socket stream-socket) seq &optional (start 0) (end (length seq)))
  (gray-stream-read-sequence socket seq start end))

(defmethod gray-streams:stream-write-sequence ((socket stream-socket) seq &optional (start 0) (end (length seq)))
  (gray-stream-write-sequence socket seq start end))

;;; Networking implementation

(defclass abcl-socket (socket)
  ((java-socket :initarg :java-socket)
   (java-channel :initarg :java-channel)))
(defclass abcl-listen-socket (listen-socket abcl-socket) ())
(defclass abcl-stream-socket (stream-socket abcl-socket) ())
(defclass abcl-datagram-socket (datagram-socket abcl-socket) ())

(defparameter *sk-jclass* (java:jclass "java.net.Socket"))
(defparameter *dsk-jclass* (java:jclass "java.net.ServerSocket"))
(defparameter *ssk-jclass* (java:jclass "java.net.DatagramSocket"))
(defparameter *sc-jclass* (java:jclass "java.nio.channels.SocketChannel"))
(defparameter *dc-jclass* (java:jclass "java.nio.channels.DatagramChannel"))
(defparameter *ssc-jclass* (java:jclass "java.nio.channels.ServerSocketChannel"))
(defparameter *selc-jclass* (java:jclass "java.nio.channels.SelectableChannel"))
(defparameter *wc-jclass* (java:jclass "java.nio.channels.WritableByteChannel"))
(defparameter *rc-jclass* (java:jclass "java.nio.channels.ReadableByteChannel"))
(defparameter *bbuf-jclass* (java:jclass "java.nio.ByteBuffer"))
(defparameter *ia-jclass* (java:jclass "java.net.InetAddress"))
(defparameter *i4a-jclass* (java:jclass "java.net.Inet4Address"))
(defparameter *i6a-jclass* (java:jclass "java.net.Inet6Address"))
(defparameter *sa-jclass* (java:jclass "java.net.SocketAddress"))
(defparameter *isa-jclass* (java:jclass "java.net.InetSocketAddress"))
(defparameter *int-jclass* (java:jclass "int"))

(defun jclose-channel (jsk)
  (let ((meth (java:jmethod *selc-jclass* "close")))
    (java:jcall meth jsk)))

(defmacro with-java-channel ((var socket) &body body)
  (let ((success (gensym "SUCCESS")))
    `(let ((,var ,socket)
	   (,success nil))
       (unwind-protect
	    (multiple-value-prog1
		(progn ,@body)
	      (setf ,success t))
	 (unless ,success
	   (jclose-channel ,var))))))

;; These are probably horribly inefficient, but I haven't found any
;; better way of doing it.
(defun make-jarray (seq &optional (start 0) (end (length seq)))
  (let ((byte (java:jclass "byte")))
    (let ((jarray (java:jnew-array byte (- end start))))
      (dotimes (i (- end start))
	(java:jcall (java:jmethod (java:jclass "java.lang.reflect.Array") "setByte" (java:jclass "java.lang.Object") *int-jclass* byte)
		    nil jarray i (elt seq (+ start i))))
      jarray)))

(defun undo-jarray (jarray &optional (into (make-array (list (java:jarray-length jarray)))) (start 0) (end (length into)))
  (dotimes (i (- end start))
    (setf (elt into (+ i start)) (java:jarray-ref jarray i)))
  into)

(defun map-socket-address (address)
  (check-type address inet-port-address)
  (java:jnew (java:jconstructor *isa-jclass* *ia-jclass* *int-jclass*)
	     (etypecase address
	       ((or ipv4-address ipv6-address)
		(java:jcall (java:jmethod *ia-jclass* "getByAddress" (java:jclass "[B")) nil
			    (make-jarray (slot-value address 'host-bytes)))))
	     (slot-value address 'port)))

(defun unmap-inet-address (jhost)
  (cond ((java:jclass-of jhost "java.net.Inet4Address")
	 (let ((jbytes (java:jcall (java:jmethod *ia-jclass* "getAddress") jhost)))
	   (make-instance 'ipv4-host-address :host-bytes (undo-jarray jbytes))))
	((java:jclass-of jhost "java.net.Inet6Address")
	 (let ((jbytes (java:jcall (java:jmethod *ia-jclass* "getAddress") jhost)))
	   (make-instance 'ipv6-host-address :host-bytes (undo-jarray jbytes))))
	(t (error "Unknown InetAddress class."))))

(defun unmap-socket-address (jaddress)
  (assert (java:jclass-of jaddress "java.net.InetSocketAddress") (jaddress))
  (let ((port (java:jcall (java:jmethod *isa-jclass* "getPort") jaddress))
	(jhost (java:jcall (java:jmethod *isa-jclass* "getAddress") jaddress)))
    (values (unmap-inet-address jhost) port)))

(defmacro retry-loop ((format-string &rest format-args) &body body)
  `(loop (with-simple-restart (:retry ,format-string ,@format-args)
	   (return ,@body))))

(defun check-not-closed (socket)
  (declare (type abcl-socket socket))
  (when (null (slot-value socket 'java-channel))
    (error 'socket-closed :socket socket)))

(defmethod close-socket ((socket abcl-socket))
  (threads:with-thread-lock (socket)
    (with-slots (java-channel) socket
      (unless (null java-channel)
	(jclose-channel java-channel)
	(setf java-channel nil)))))

(defmethod socket-open-p ((socket abcl-socket))
  (threads:with-thread-lock (socket)
    (if (slot-value socket 'java-channel) t nil)))

(defmethod socket-local-address ((socket abcl-stream-socket))
  (multiple-value-bind (host port)
      (unmap-socket-address
       (threads:with-thread-lock (socket)
	 (check-not-closed socket)
	 (java:jcall (java:jmethod *sk-jclass* "getLocalSocketAddress") (slot-value socket 'java-socket))))
    (etypecase host
      (ipv4-address (make-instance 'tcp4-address :port port :host-address host))
      (ipv6-address (make-instance 'tcp6-address :port port :host-address host)))))

(defmethod socket-remote-address ((socket abcl-stream-socket))
  (multiple-value-bind (host port)
      (unmap-socket-address
       (threads:with-thread-lock (socket)
	 (check-not-closed socket)
	 (java:jcall (java:jmethod *sk-jclass* "getRemoteSocketAddress") (slot-value socket 'java-socket))))
    (etypecase host
      (ipv4-address (make-instance 'tcp4-address :port port :host-address host))
      (ipv6-address (make-instance 'tcp6-address :port port :host-address host)))))

(defmethod socket-send ((socket abcl-stream-socket) buf &key (start 0) (end (length buf)) no-hang)
  (threads:with-thread-lock (socket)
    (check-not-closed socket)
    (with-slots (java-channel) socket
      (unwind-protect
	   (progn
	     (when no-hang
	       (java:jcall (java:jmethod *selc-jclass* "configureBlocking" (java:jclass "boolean")) java-channel (java:make-immediate-object nil :boolean)))
	     (retry-loop ("Retry the send operation.")
	       (java:jcall (java:jmethod *wc-jclass* "write" *bbuf-jclass*) java-channel
			   (java:jcall (java:jmethod *bbuf-jclass* "wrap" (java:jclass "[B")) nil (make-jarray buf start end)))))
	(java:jcall (java:jmethod *selc-jclass* "configureBlocking" (java:jclass "boolean")) java-channel (java:make-immediate-object t :boolean))))))

(defmethod socket-recv-into ((socket abcl-stream-socket) buf &key (start 0) (end (length buf)) no-hang)
  (threads:with-thread-lock (socket)
    (check-not-closed socket)
    (with-slots (java-channel) socket
      (unwind-protect
	   (progn
	     (when no-hang
	       (java:jcall (java:jmethod *selc-jclass* "configureBlocking" (java:jclass "boolean")) java-channel (java:make-immediate-object nil :boolean)))
	     (retry-loop ("Try receiving again.")
	       (let* ((jbuf (java:jnew-array (java:jclass "byte") (- end start)))
		      (ret (java:jcall (java:jmethod *rc-jclass* "read" *bbuf-jclass*) java-channel
				       (java:jcall (java:jmethod *bbuf-jclass* "wrap" (java:jclass "[B")) nil jbuf))))
		 (if (< ret 0)
		     (values nil nil)
		     (progn
		       (undo-jarray jbuf buf start end)
		       (values ret nil))))))
	(java:jcall (java:jmethod *selc-jclass* "configureBlocking" (java:jclass "boolean")) java-channel (java:make-immediate-object t :boolean))))))

(defmethod connect-to-address ((address tcp-address) &key local)
  (let ((ch
	 (retry-loop ("Try connecting again.")
	   (with-java-channel (ch (java:jcall (java:jmethod *sc-jclass* "open") nil))
	     (let ((sk (java:jcall (java:jmethod *sc-jclass* "socket") ch)))
	       (when local
		 (java:jcall (java:jmethod *sk-jclass* "bind" *sa-jclass*) sk (map-socket-address local)))
	       (java:jcall (java:jmethod *sk-jclass* "connect" *sa-jclass*) sk (map-socket-address address)))
	     ch))))
    (make-instance 'abcl-stream-socket
		   :java-channel ch
		   :java-socket (java:jcall (java:jmethod *sc-jclass* "socket") ch))))
