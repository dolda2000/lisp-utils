#-sbcl (error "No known socket interface for ~a" (lisp-implementation-type))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require 'sb-bsd-sockets))
(defpackage :lirc (:use :cl :sb-bsd-sockets))
(in-package :lirc)

(defvar *socket* nil)
(defvar *translations* (make-hash-table :test 'equal))
(defvar *bindings* '())
(defvar *button* nil)
(defvar *button-repeat* 0)
(defvar *button-name* "")
(defvar *button-remote* "")

(defun disconnect ()
  (if *socket*
      (close (prog1 *socket*
	       (setf *socket* nil)))))

(defun connect (&key (socket "/dev/lircd"))
  (disconnect)
  (setf *socket* (let ((sk (make-instance 'local-socket :type :stream)))
		   (socket-connect sk socket)
		   (socket-make-stream sk :input t :output t)))
  (values))

(defun read-delim (in delim)
  (let ((buf (make-array '(16) :element-type 'character :adjustable t :fill-pointer 0)))
    (loop (let ((b (read-char in nil delim)))
	    (if (eq b delim)
		(return (subseq buf 0 (fill-pointer buf)))
		(vector-push-extend b buf))))))

;(defun bytevec->string (vec)
;  (map 'string #'code-char vec))

(defun get-keypress-raw ()
  (if (null *socket*)
      (error "Not connected to lircd"))
  (with-input-from-string (lin (read-delim *socket* #\newline))
    (let* ((code (read-delim lin #\space))
	   (repeat (read-delim lin #\space))
	   (name (read-delim lin #\space))
	   (remote (read-delim lin #\space)))
      (declare (type string code repeat name remote))
      (values name remote (parse-integer repeat :radix 16) (parse-integer code :radix 16)))))

(defun def-translation (symbol key &optional remote)
  (setf (gethash (if remote
		     (list (string-upcase remote)
			   (string-upcase key))
		     (string-upcase key))
		 *translations*) symbol))

(defun translate (remote key)
  (setf remote (string-upcase remote)
	key (string-upcase key))
  (cond ((gethash (list remote key) *translations*))
	((gethash key *translations*))
	((intern key (find-package 'keyword)))))

(defun get-keypress ()
  (multiple-value-bind (key remote repeat)
      (get-keypress-raw)
    (values (translate remote key) repeat)))

(defun get-bindings (key)
  (mapcar #'first
	  (stable-sort (let ((ret '()))
			 (dolist (binding *bindings* ret)
			   (multiple-value-bind (sel when prio fun)
			       (values-list binding)
			     (if (and (ecase when
					((:first) (eq ret '()))
					((:always) t))
				      (etypecase sel
					(symbol (or (eq sel t)
						    (eq sel key)))
					(function (funcall sel key))))
				 (setf ret (append ret `((,fun ,prio))))))))
		       #'> :key #'second)))

(defmacro defkey (key &body body)
  `(push (list ,key :first 0 #'(lambda () ,@body))
	 *bindings*))

(defmacro with-bound-keys* (bindings defwhen defprio &body body)
  (let ((blist (mapcar #'(lambda (binding)
			   (destructuring-bind ((key &key (prio defprio) (when defwhen)) &body body)
			       binding
			       `(list ,key ,when ,prio #'(lambda () ,@body))))
		       bindings)))
    `(let ((*bindings* (list* ,@blist *bindings*)))
       ,@body)))

(defmacro with-bound-keys (bindings &body body)
  `(with-bound-keys* ,bindings :always 0 ,@body))

(defmacro keycase (&rest bindings)
  `(multiple-value-bind (name remote repeat)
       (get-keypress-raw)
     (let* ((*button* (translate remote name))
	    (*button-name* name)
	    (*button-remote* remote)
	    (*button-repeat* repeat)
	    (handlers (with-bound-keys* ,bindings :first 0
			(get-bindings *button*))))
       (restart-case
	   (let ((first t)
		 (ret '()))
	     (dolist (handler handlers (values-list ret))
	       (restart-case 
		   (let ((ret2 (multiple-value-list (funcall handler))))
		     (if first
			 (setf first nil
			       ret ret2)))
		 (ignore-handler ()
		   :report "Ignore this key handler"
		   nil))))
	 (ignore-key ()
	   :report "Ignore this key press and return NIL from KEYCASE"
	   nil)))))

(defmacro keyloop (&rest bindings)
  (let ((start (gensym "START")))
    `(block nil
       (tagbody
	  ,start
	  (keycase ,@bindings)
	  (go ,start)))))

(export '(connect disconnect
	  def-translation get-keypress
	  *button* *button-repeat* *button-name* *button-remote*
	  defkey with-bound-keys keycase keyloop ignore-key ignore-handler))
(provide :lirc)
