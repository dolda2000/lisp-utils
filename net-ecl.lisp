(in-package :common-net)

(require :sb-bsd-sockets)

;;; Gray stream methods

;; Redefine stream-socket with Gray superclasses. I know it's ugly,
;; but I just don't know of a better way to do it.
(defclass stream-socket (socket gray:fundamental-input-stream gray:fundamental-output-stream)
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
		  ,(intern (symbol-name name) (find-package :gray)) ((socket stream-socket))
		(,(intern (concatenate 'string "GRAY-" (symbol-name name)) (symbol-package 'stream-socket)) socket)))
	   (simple-null (name)
	     `(defmethod
		  ,(intern (symbol-name name) (find-package :gray)) ((socket stream-socket))
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

(defmethod gray:stream-write-byte ((socket stream-socket) byte)
  (gray-stream-write-char socket byte))

(defmethod gray:stream-unread-char ((socket stream-socket) char)
  (gray-stream-unread-char socket char))

(defmethod gray:stream-write-char ((socket stream-socket) char)
  (gray-stream-write-char socket char))

(defmethod gray:close ((socket stream-socket) &key abort)
  (declare (ignore abort))
  (prog1
      (call-next-method)
    (close-socket socket)))

(defmethod gray:stream-start-line-p ((socket stream-socket))
  (eql (gray:stream-line-column socket) 0))

(defmethod gray:stream-fresh-line ((socket stream-socket))
  (unless (gray:stream-start-line-p socket)
    (gray:stream-terpri socket)
    t))

(defmethod gray:stream-write-string ((socket stream-socket) string &optional (start 0) (end (length string)))
  (gray:stream-write-sequence socket string start end))

(defmethod gray:stream-terpri ((socket stream-socket))
  (gray:stream-write-char socket #\newline))

(defmethod gray:stream-read-sequence ((socket stream-socket) seq &optional (start 0) (end (length seq)))
  (gray-stream-read-sequence socket seq start end))

(defmethod gray:stream-write-sequence ((socket stream-socket) seq &optional (start 0) (end (length seq)))
  (gray-stream-write-sequence socket seq start end))
