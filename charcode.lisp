;;;; CHAR-CODE -- Conversions between characters and byte
;;;; representations thereof

(defpackage :charcode
  (:use :cl #+sbcl :sb-gray #-sbcl :gray)
  (:export "MAKE-ENCODER" "MAKE-DECODER" "ENCODE-STRING" "DECODE-STRING" "SYSTEM-CHARSET"
	   "CODING-ERROR"
	   "MAKE-CODEC-CHARACTER-STREAM"
	   "ASCII" "LATIN-1" "LATIN1" "UTF-8" "UTF8"))
(in-package :charcode)

;;; General stuff

(define-condition coding-error (error)
  ((input :initarg :input)
   (position :initarg :position)
   (result :initarg :result)))

(define-condition simple-coding-error (coding-error simple-error) ())

(defun coding-error (input position result format &rest format-args)
  (error 'simple-coding-error
	 :input input :position position :result result
	 :format-control format :format-arguments format-args))

(deftype decoder-fun () `(function ((array (unsigned-byte 8))
				    (array character)
				    &key (start fixnum) (end fixnum))
				   (member t nil)))
(deftype encoder-fun () `(function ((array character)
				    (array (unsigned-byte 8))
				    &key (start fixnum) (end fixnum))
				   (member t nil)))

(defmacro define-encoder ((name) &body make-encoder)
  `(setf (get ',name 'make-encoder) #'(lambda () ,@make-encoder)))

(defmacro define-decoder ((name) &body make-decoder)
  `(setf (get ',name 'make-decoder) #'(lambda () ,@make-decoder)))

(defmacro define-codec-synonyms (name &rest synonyms)
  `(eval-when (:load-toplevel :execute)
     ,@(mapcar #'(lambda (sym)
		   `(setf (get ',sym 'make-encoder) (get ',name 'make-encoder)
			  (get ',sym 'make-decoder) (get ',name 'make-decoder)))
	       synonyms)))

(defun make-encoder (name)
  (the encoder-fun (values (funcall (get name 'make-encoder)))))

(defun make-decoder (name)
  (the decoder-fun (values (funcall (get name 'make-decoder)))))

(defun system-charset ()
  ;; XXX: Replace me with something perhaps more sensible.
  'utf-8)

(defun encode-string (string &optional (coding (system-charset)))
  (declare (type string string))
  (let ((encoder (make-encoder coding))
	(buf (make-array (list (length string)) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (unless (funcall encoder string buf)
      (coding-error string (length string) buf "Encoding of string in ~A ended prematurely." coding))
    buf))

(defun decode-string (buffer &optional (coding (system-charset)))
  (declare (type (array (unsigned-byte 8)) buffer))
  (let ((decoder (make-decoder coding))
	(buf (make-array (list (length buffer)) :element-type 'character :adjustable t :fill-pointer 0)))
    (unless (funcall decoder buffer buf)
      (coding-error buffer (length buffer) buf "~A byte sequence ended prematurely." coding))
    buf))

;;; Gray stream implementation

(defclass codec-character-stream (fundamental-character-input-stream fundamental-character-output-stream)
  ((decoder :initarg :decoder)
   (encoder :initarg :encoder)
   (back :initarg :back)
   (read-pos :initform 0)
   (buffer :initform (make-array '(64) :element-type 'character :adjustable t :fill-pointer 0))))

(defun make-codec-character-stream (real-stream &optional (charset (system-charset)))
  (declare (type stream real-stream))
  (make-instance 'codec-character-stream :decoder (make-decoder charset) :encoder (make-encoder charset) :back real-stream))

(defmethod close ((stream codec-character-stream) &key abort)
  (with-slots (back) stream
    (close back :abort abort))
  (call-next-method))

(defmethod open-stream-p ((stream codec-character-stream))
  (with-slots (back) stream
    (open-stream-p stream)))

(defun ccs-ensure-buffer (stream len)
  (declare (type codec-character-stream stream)
	   (type integer len))
  (with-slots (decoder back buffer read-pos) stream
    (let ((readbuf (make-array (list len) :element-type '(unsigned-byte 8))))
      (loop (unless (< (- (length buffer) read-pos) len) (return t))
	 (let ((readlen (read-sequence readbuf back :end (- len (- (length buffer) read-pos)))))
	   (when (= readlen 0)
	     (return-from ccs-ensure-buffer nil))
	   (funcall decoder readbuf buffer :end readlen))))))

(defun ccs-clear-buffer (stream)
  (declare (type codec-character-stream stream))
  (with-slots (read-pos buffer) stream
    (replace buffer buffer :start2 read-pos)
    (setf (fill-pointer buffer) (- (fill-pointer buffer) read-pos)
	  read-pos 0)))

(defmethod stream-read-char ((stream codec-character-stream))
  (unless (ccs-ensure-buffer stream 1)
    (return-from stream-read-char :eof))
  (with-slots (read-pos buffer) stream
    (prog1 (aref buffer read-pos)
      (when (>= (incf read-pos) 16)
	(ccs-clear-buffer stream)))))

(defmethod stream-unread-char ((stream codec-character-stream) char)
  (with-slots (read-pos buffer) stream
    (when (= read-pos 0)
      (let ((len (length buffer)))
	(when (< (array-dimension buffer 0) (+ len 16))
	  (adjust-array buffer (list (setf (fill-pointer buffer)
					   (+ len 16)))))
	(replace buffer buffer :start1 16 :end2 len)))
    (setf (aref buffer (decf read-pos)) char)
    nil))

(defun ccs-wont-hang-p (stream)
  (declare (type codec-character-stream stream))
  (with-slots (read-pos back buffer) stream
    (or (and (< read-pos (length buffer)) (aref buffer read-pos))
	(listen back))))

(defmethod stream-read-char-no-hang ((stream codec-character-stream))
  (if (ccs-wont-hang-p stream)
      (stream-read-char stream)
      nil))

(defmethod stream-peek-char ((stream codec-character-stream))
  (unless (ccs-ensure-buffer stream 1)
    (return-from stream-peek-char :eof))
  (with-slots (read-pos buffer) stream
    (aref buffer read-pos)))

(defmethod stream-listen ((stream codec-character-stream))
  (if (ccs-wont-hang-p stream)
      (let ((peek (stream-peek-char stream)))
	(if (eq peek :eof)
	    nil
	    peek))
      nil))

(defmethod stream-write-char ((stream codec-character-stream) char)
  (with-slots (encoder back) stream
    (let ((seq (make-array '(1) :element-type 'character :initial-element char))
	  (outbuf (make-array '(16) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
      (funcall encoder seq outbuf)
      (write-sequence outbuf back))))

(defmethod stream-finish-output ((stream codec-character-stream))
  (finish-output (slot-value stream 'back)))

(defmethod stream-force-output ((stream codec-character-stream))
  (force-output (slot-value stream 'back)))

(defmethod stream-read-sequence ((stream codec-character-stream) seq &optional (start 0) (end (length seq)))
  (ccs-ensure-buffer stream (- end start))
  (with-slots (read-pos buffer) stream
    (replace seq buffer :start1 start :end1 end :start2 read-pos :end2 (length buffer))
    (let ((len (min (- end start) (- (length buffer) read-pos))))
      (when (>= (incf read-pos len) 128)
	(ccs-clear-buffer stream)))))

(defmethod stream-write-sequence ((stream codec-character-stream) seq &optional (start 0) (end (length seq)))
  (with-slots (encoder back) stream
    (let ((outbuf (make-array (list (- end start)) :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
      (funcall encoder seq outbuf)
      (write-sequence outbuf back))))

;;; Implementation-specific functions

#+(or (and clisp unicode) sbcl)
(defun unicode->char (unicode)
  (declare (type (unsigned-byte 24) unicode))
  (code-char unicode))

#+(or (and clisp unicode) sbcl)
(defun char->unicode (char)
  (declare (type character char))
  (char-code char))

;;; ASCII

(defun decode-ascii (byteseq charseq &key (start 0) (end (length byteseq)))
  (declare (type (array (unsigned-byte 8)) byteseq)
	   (type (array character) charseq)
	   (type fixnum start end))
  (loop
     (restart-case
	 (loop
	    (unless (< start end) (return-from decode-ascii t))
	    (let ((byte (aref byteseq (prog1 start (incf start)))))
	      (unless (< byte 128)
		(coding-error byteseq start charseq "Invalid byte ~D in ASCII stream." byte))
	      (vector-push-extend (unicode->char byte) charseq)))
       (:replace-char (&optional (replacement (unicode->char #xfffd)))
	 :report "Replace the invalid byte with a character."
	 (vector-push-extend replacement charseq))
       (:skip-char ()
	 :report "Ignore the invalid byte."
	 nil))))

(defun encode-ascii (charseq byteseq &key (start 0) (end (length charseq)))
  (declare (type (array (unsigned-byte 8)) byteseq)
	   (type (array character) charseq)
	   (type fixnum start end))
  (loop
     (restart-case
	 (loop
	    (unless (< start end) (return-from encode-ascii t))
	    (vector-push-extend (let ((cp (char->unicode (aref charseq (prog1 start (incf start))))))
				  (unless (< cp 128)
				    (coding-error charseq start byteseq "ASCII cannot encode code-points higher than 128."))
				  cp)
				byteseq))
       (:replace-char (&optional (replacement #\?))
	 :report "Replace this character with another."
	 (vector-push-extend (char->unicode replacement) byteseq))
       (:skip-char ()
	 :report "Ignore this character."
	 nil))))

(define-decoder (ascii)
  #'decode-ascii)

(define-encoder (ascii)
  #'encode-ascii)

(define-codec-synonyms ascii :ascii)

;;; Latin-1

(defun decode-latin-1 (byteseq charseq &key (start 0) (end (length byteseq)))
  (declare (type (array (unsigned-byte 8)) byteseq)
	   (type (array character) charseq)
	   (type fixnum start end))
  (do ((i start (1+ i)))
      ((>= i end))
    (vector-push-extend (unicode->char (aref byteseq i)) charseq))
  t)

(defun encode-latin-1 (charseq byteseq &key (start 0) (end (length charseq)))
  (declare (type (array (unsigned-byte 8)) byteseq)
	   (type (array character) charseq)
	   (type fixnum start end))
  (loop
     (restart-case
	 (loop
	    (unless (< start end) (return-from encode-latin-1 t))
	    (vector-push-extend (let ((cp (char->unicode (aref charseq (prog1 start (incf start))))))
				  (unless (< cp 256)
				    (coding-error charseq start byteseq "ISO-8859-1 cannot encode code-points higher than 256."))
				  cp)
				byteseq))
       (:replace-char (&optional (replacement #\?))
	 :report "Replace this character with another."
	 (vector-push-extend (char->unicode replacement) byteseq))
       (:skip-char ()
	 :report "Ignore this character."
	 nil))))

(define-decoder (latin-1)
  #'decode-latin-1)

(define-encoder (latin-1)
  #'encode-latin-1)

(define-codec-synonyms latin-1 latin1 iso-8859-1 :latin-1 :latin1 :iso-8859-1)

;;; UTF-8

(defun encode-utf-8 (charseq byteseq &key (start 0) (end (length charseq)))
  (declare (type (array (unsigned-byte 8)) byteseq)
	   (type (array character) charseq)
	   (type fixnum start end))
  (do ((i start (1+ i)))
      ((>= i end))
    (let ((cp (char->unicode (aref charseq i))))
      (if (< cp 128)
	  (vector-push-extend cp byteseq)
	  (let ((nbytes 0)
		(bytes '()))
	    (loop
	       (push (logior (ldb (byte 6 0) cp) #x80) bytes)
	       (setf cp (truncate cp 64))
	       (incf nbytes)
	       (when (< cp (expt 2 (- 6 nbytes)))
		 (push (logior (logand #xff (lognot (1- (expt 2 (- 7 nbytes)))))
			       cp)
		       bytes)
		 (return)))
	    (dolist (byte bytes)
	      (vector-push-extend byte byteseq))))))
  t)

(define-encoder (utf-8)
  #'encode-utf-8)

(define-decoder (utf-8)
  (let ((mbuf 0)
	(mlen 0))
    (flet ((decode (byteseq charseq &key (start 0) (end (length byteseq)))
		  (declare (type (array (unsigned-byte 8)) byteseq)
			   (type (array character) charseq)
			   (type fixnum start end))
	     (let ((i start))
	       (flet ((failure (format &rest args)
			(error 'simple-coding-error
			       :input byteseq :position i :result charseq
			       :format-control format :format-arguments args)))
		 (loop
		    (restart-case
			(progn
			  (loop
			     (unless (< i end) (return))
			     (let ((byte (aref byteseq (prog1 i (incf i)))))
			       (if (= mlen 0)
				   (if (< byte 128)
				       (vector-push-extend (unicode->char byte) charseq)
				       (setf mlen (block zero
						    (dotimes (i 7)
						      (when (= (ldb (byte 1 (- 7 i)) byte) 0)
							(when (< i 2)
							  (failure "UTF-8 sequence started with continuation byte: ~D" byte))
							(return-from zero (1- i))))
						    (failure "Invalid UTF-8 sequence start byte: ~D" byte))
					     mbuf (ldb (byte (- 6 mlen) 0) byte)))
				   (progn (when (not (= (ldb (byte 2 6) byte) 2))
					    (failure "Invalid UTF-8 continuation byte: ~D" byte))
					  (setf mbuf (+ (* mbuf 64) (ldb (byte 6 0) byte)))
					  (when (= (decf mlen) 0)
					    (when (< mbuf 128)
					      (with-simple-restart (:accept "Accept anyway.")
						(failure "UTF-8 multibyte sequence denoted an ASCII character ~S (either an encoding error or an attempt at breaking security)." (unicode->char mbuf))))
					    (vector-push-extend (unicode->char mbuf) charseq))))))
			  (return-from decode (= mlen 0)))
		      (:replace-char (&optional (replacement (unicode->char #xfffd)))
			:report "Replace the invalid bytes with a character."
			(vector-push-extend replacement charseq)
			(loop (unless (and (< i end) (= (ldb (byte 2 6) (aref byteseq i)) 2))
				(return))
			   (incf i))
			(setf mlen 0))
		      (:skip-char ()
			:report "Ignore the invalid byte sequence."
			(loop (unless (and (< i end) (= (ldb (byte 2 6) (aref byteseq i)) 2))
				(return))
			   (incf i))
			(setf mlen 0))))))))
      #'decode)))

(define-codec-synonyms utf-8 utf8 :utf-8 :utf8)
