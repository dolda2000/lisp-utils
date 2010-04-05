;;;; MPCL -- Common Lisp MPD Client library

#-sbcl (error "No known socket interface for ~a" (lisp-implementation-type))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require 'sb-bsd-sockets)
  (require 'cl-ppcre))
(defpackage :mpcl (:use :cl :sb-bsd-sockets))
(in-package :mpcl)

;;; Global variables
(defvar *socket* nil)
(defvar *last-command* 0)
(defvar *last-server* nil)
(defvar *retries* 0)
#+sbcl (defvar *conn-lock* (sb-thread:make-mutex))

;;; Utility functions
(defmacro concat (&rest strings)
  `(concatenate 'string ,@strings))

(defun assert-type (type val)
  (assert (typep val type))
  val)

(defun clipnum (num min max)
  (cond ((< num min) min)
	((> num max) max)
	(t num)))

(defmacro regex-cond (key &body clauses)
  (let ((match (gensym))
	(sub (gensym))
	(val (gensym))
	(block-nm (gensym)))
    (flet ((ctrans (clause)
	     (if (eq (first clause) 'otherwise)
		 `(return-from ,block-nm
		    (progn ,@(rest clause)))
		 (destructuring-bind (regex arglist &body body)
		     clause
		   `(multiple-value-bind (,match ,sub)
			(ppcre:scan-to-strings ,regex ,val)
		      ,@(if (null arglist)
			    `((declare (ignore ,sub))))
		      (if ,match
			  (return-from ,block-nm
			    (let ,(let ((argno 0))
				       (mapcar #'(lambda (arg)
						   (prog1 `(,arg (aref ,sub ,argno))
						     (incf argno)))
					       arglist))
			      ,@body))))))))
      `(block ,block-nm
	 (let ((,val (the string ,key)))
	   ,@(mapcar #'ctrans clauses))))))

;;; Error conditions
(define-condition protocol-error (error)
  ((message :reader protocol-error-message
	    :initarg :message
	    :type string)
   (real-error :reader protocol-error-cause
	       :initarg :cause
	       :type condition
	       :initform nil)
   (retries :reader protocol-error-retries
	    :initarg :retries
	    :type integer
	    :initform 0))
  (:report (lambda (c s)
	     (if (protocol-error-cause c)
		 (format s "~A: ~A" (protocol-error-message c) (protocol-error-cause c))
		 (format s "Protocol error occurred on mpd socket: ~A" (protocol-error-message c))))))

(define-condition protocol-input-error (protocol-error)
  ((inputs :reader protocol-error-inputs
	   :initarg :inputs))
  (:report (lambda (c s)
	     (apply #'format s (protocol-error-message c) (protocol-error-inputs c)))))

(define-condition command-error (error)
  ((err-code :reader command-error-code
	     :initarg :err-code
	     :type integer)
   (message :reader command-error-message
	    :initarg :message
	    :type string))
  (:report (lambda (c s)
	     (format s "mpd error response: ~A" (command-error-message c)))))

(defvar *command-error-types* (make-hash-table))

(defmacro def-command-error-type (code name desc)
  (let ((cond-sym (intern (concat "COMMAND-ERROR-" (symbol-name name)))))
    `(progn (define-condition ,cond-sym (command-error)
	      ()
	      (:report (lambda (c s)
			 (format s "mpd error response: ~A (message was: `~A')" ,desc (command-error-message c)))))
	    (setf (gethash ,code *command-error-types*) ',cond-sym)
	    (export '(,cond-sym)))))
;; The following are fetched from libmpdclient.h. In all honesty, I
;; can't really figure out what they mean just from their names, so
;; the descriptions aren't optimal in every conceivable way.
(def-command-error-type 1 not-list "not list")
(def-command-error-type 2 arg "argument")
(def-command-error-type 3 password "bad password")
(def-command-error-type 4 permission "permission denied")
(def-command-error-type 5 unknown-cmd "unknown command")
(def-command-error-type 50 no-exist "item does not exist")
(def-command-error-type 51 playlist-max "playlist overload") ; ?!
(def-command-error-type 52 system "system error")
(def-command-error-type 53 playlist-load "could not load playlist")
(def-command-error-type 54 update-already "already updated") ; ?!
(def-command-error-type 55 player-sync "player sync")	     ; ?!
(def-command-error-type 56 exist "item already exists")

(export '(protocol-error reconnect command-error
	  protocol-error-retries command-error-code
	  command-error-message))

;;; Struct definitions
(defstruct song
  (file "" :type string)
  (id -1 :type integer)
  (pos -1 :type integer)
  (length -1 :type integer)
  (track -1 :type integer)
  artist title album genre composer date)

(export '(song
	  song-file song-id song-pos song-length song-track
	  song-artist song-title song-album song-genre
	  song-composer song-date))

(defstruct status
  (volume 0 :type integer)
  (playlist-version -1 :type integer)
  (num-songs 0 :type integer)
  (song -1 :type integer)
  (songid -1 :type integer)
  (pos -1 :type integer)
  (song-len -1 :type integer)
  repeat repeat-song random state)

;;; Basic protocol management
#+sbcl (defmacro with-conn-lock (&body body)
	 `(sb-thread:with-recursive-lock (*conn-lock*) ,@body))
#-sbcl (defmacro with-conn-lock (&body body)
	 body)

(defun disconnect ()
  "Disconnect from MPD."
  (with-conn-lock
    (let ((sk (prog1 *socket* (setf *socket* nil))))
      (when sk (handler-case
		   (close sk)
		 (error () (close sk :abort t)))))))

(defun connection-error (condition-type &rest condition-args)
  (disconnect)
  (error (apply #'make-condition condition-type :retries *retries* condition-args)))

(defun command-error (code message)
  (error (funcall #'make-condition (gethash code *command-error-types* 'command-error)
		  :err-code code
		  :message message)))

(defun get-response ()
  (let ((ret '()) (last nil))
    (loop (let ((line (handler-case
			  (read-line *socket*)
			(error (err)
			  (connection-error 'protocol-error
					    :message "Socket read error"
					    :cause err)))))
	    (regex-cond line
	      ("^OK( .*)?$"
	       ()
	       (return ret))
	      ("^ACK \\[(\\d+)@(\\d+)\\] \\{([^\\}]*)\\} (.*)$"
	       (code list-pos command rest)
	       (declare (ignore list-pos command))
	       (command-error (parse-integer code) rest))
	      ("^([^:]+): (.*)$"
	       (key val)
	       (let ((new (list (cons (intern (string-upcase key) (find-package 'keyword))
				      val))))
		 (if last
		     (setf (cdr last) new last new)
		     (setf ret new last new))))
	      (otherwise
	       (connection-error 'protocol-input-error
				 :message "Invalid response from mpd: ~A"
				 :inputs (list line))))))))

(defun default-host ()
  (block nil
    #+sbcl (let ((host (sb-posix:getenv "MPD_HOST")))
	     (when host (return host)))
    "localhost"))

(defun default-port ()
  (block nil
    #+sbcl (let ((port (sb-posix:getenv "MPD_PORT")))
	     (when port (return (parse-integer port))))
    6600))

(defun connect (&key (host (default-host)) (port (default-port)))
  "Connect to a running MPD."
  (disconnect)
  (with-conn-lock
    (setf *socket* (block outer
		     (let ((last-err nil))
		       (dolist (address (host-ent-addresses (get-host-by-name host)))
			 (handler-case
			     (let ((sk (make-instance 'inet-socket :type :stream)))
			       (socket-connect sk address port)
			       (return-from outer (socket-make-stream sk :input t :output t :buffering :none)))
			   (error (err)
			     (setf last-err err)
			     (warn "mpd connection failure on address ~A: ~A" address err))))
		       (if last-err
			   (error "Could not connect to mpd: ~A" last-err)
			   (error "Could not connect to mpd: host name `~A' did not resolve to any addreses" host)))))
    (setf *last-server* (cons host port))
    (setf *last-command* (get-universal-time))
    (get-response)))

(defmacro dovector ((var vec) &body body)
  (let ((i (gensym)))
    `(dotimes (,i (length ,vec))
       (let ((,var (aref ,vec ,i)))
	 ,@body))))

(defmacro with-push-vector ((push-fun type &key (init-length 16)) &body body)
  (let ((vec (gensym)))
    `(let ((,vec (make-array (list ,init-length) :element-type ',type :adjustable t :fill-pointer 0)))
       (flet ((,push-fun (el)
		(declare (type ,type el))
		(vector-push-extend el ,vec)))
	 ,@body)
       ,vec)))

(defun quote-argument (arg)
  (declare (type string arg))
  (if (= (length arg) 0)
      "\"\""
      (let* ((quote nil)
	     (res (with-push-vector (add character)
		    (dovector (elt arg)
		      (case elt
			((#\space #\tab)
			 (setf quote t) (add elt))
			((#\")
			 (setf quote t) (add #\\) (add #\"))
			((#\newline)
			 (error "Cannot send strings containing newlines to mpd: ~S" arg))
			(t (add elt)))))))
	(if quote
	    (concat "\"" res "\"")
	    res))))

(defun arg-to-string (arg)
  (quote-argument
   (typecase arg
     (string arg)
     (t (write-to-string arg :escape nil)))))

(defun mpd-command (&rest words)
  (with-conn-lock
    (let ((*retries* 0))
      (loop
	 (restart-case
	     (progn (if (null *socket*)
			(connection-error 'protocol-error
					  :message "Not connected to mpd"))
		    (handler-case
			(progn (write-string (reduce #'(lambda (a b) (concat a " " b))
						     (mapcar #'arg-to-string words))
					     *socket*)
			       (terpri *socket*)
			       (force-output *socket*))
		      (error (err)
			(connection-error 'protocol-error
					  :message "Socket write error"
					  :cause err)))
		    (setf *last-command* (get-universal-time))
		    (return (get-response)))
	   (reconnect ()
	     :test (lambda (c) (and (typep c 'protocol-error) (not (null *last-server*))))
	     :report (lambda (s)
		       (format s "Reconnect to ~A:~D and try again (~D retries so far)" (car *last-server*) (cdr *last-server*) *retries*))
	     (incf *retries*)
	     (connect :host (car *last-server*)
		      :port (cdr *last-server*))))))))

(export '(connect disconnect))

;;; Slot parsers
;; These, and the structures themselves, should probably be rewritten
;; using macros instead. There's a lot of redundancy.
(defun cons-status (info)
  (let ((ret (make-status)))
    (dolist (line info ret)
      (handler-case 
	  (case (car line)
	    ((:time)
	     (let ((pos (assert-type '(integer 0 *) (position #\: (cdr line)))))
	       (setf (status-pos ret) (parse-integer (subseq (cdr line) 0 pos))
		     (status-song-len ret) (parse-integer (subseq (cdr line) (1+ pos))))))
	    ((:state) (setf (status-state ret) (intern (string-upcase (cdr line)) (find-package 'keyword))))
	    ((:repeat) (setf (status-repeat ret) (not (equal (cdr line) "0"))))
	    ((:repeatsong) (setf (status-repeat-song ret) (not (equal (cdr line) "0"))))
	    ((:random) (setf (status-random ret) (not (equal (cdr line) "0"))))
	    ((:volume) (setf (status-volume ret) (parse-integer (cdr line))))
	    ((:playlistlength) (setf (status-num-songs ret) (parse-integer (cdr line))))
	    ((:song) (setf (status-song ret) (parse-integer (cdr line))))
	    ((:songid) (setf (status-songid ret) (parse-integer (cdr line))))
	    ((:playlist) (setf (status-playlist-version ret) (parse-integer (cdr line))))
	    ;; Ignored:
	    ((:xfade :bitrate :audio))
	    (t (warn "Unknown status slot ~A" (car line))))
	(parse-error ()
	  (warn "Status slot parse error in ~S, slot was ~S" ret line))))))

(defun song-list (info)
  (let ((ret '()) (cur nil))
    (dolist (line info ret)
      (handler-case 
	  (case (car line)
	    ((:file)
	     (setf cur (make-song :file (cdr line)))
	     (setf ret (nconc ret (list cur))))
	    ((:time) (setf (song-length cur) (parse-integer (cdr line))))
	    ((:id) (setf (song-id cur) (parse-integer (cdr line))))
	    ((:pos) (setf (song-pos cur) (parse-integer (cdr line))))
	    ((:track) (setf (song-track cur) (parse-integer (cdr line))))
	    ((:title) (setf (song-title cur) (cdr line)))
	    ((:album) (setf (song-album cur) (cdr line)))
	    ((:artist) (setf (song-artist cur) (cdr line)))
	    ((:genre) (setf (song-genre cur) (cdr line)))
	    ((:composer) (setf (song-composer cur) (cdr line)))
	    ((:date) (setf (song-date cur) (cdr line)))
	    (t (warn "Unknown song slot ~A" (car line))))
	(parse-error ()
	  (warn "Song slot parse error in ~A, slot was ~A" cur line))))))

;;; Functions for individual commands
(defun status ()
  "Fetch and return the current status of the MPD as a STATUS structure."
  (cons-status (mpd-command "status")))

(defmacro with-status (slots &body body)
  "Fetch the current status of the MPD, and then run BODY with the
variables in the SLOTS bound to their curresponding status items.
Available slots are:

  STATE (SYMBOL)
    The current state of the MPD
    Known values are :STOP, :PAUSE and :PLAY
  VOLUME (INTEGER 0 100)
    Current output volume
  PLAYLIST-VERSION (INTEGER 0 *)
    Increases by one each time the playlist changes
  NUM-SONGS (INTEGER 0 *)
    Number of songs in the playlist
  SONG (INTEGER 0 NUM-SONGS)
    Index, in the playlist, of the currently playing song
  SONGID (INTEGER)
    ID of the currently playing song
  SONG-LEN (INTEGER 0 *)
    Length, in seconds, of currently playing song
  POS (INTEGER 0 SONG-LEN)
    Current time position of the currently playing song, in seconds
  REPEAT (NIL or T)
    Non-NIL if the MPD is in repeat mode
  REPEAT-SONG (NIL or T)
    Non-NIL if the MPD is repeating the current song
    (not available without patching)
  RANDOM (NIL or T)
    Non-NIL if the MPD is in random mode"
  (let ((status (gensym "STATUS")))
    `(let* ((,status (status))
	    ;; This is kinda ugly, but I don't really know any better
	    ;; way to do it with structs.
	    ,@(mapcar #'(lambda (slot-sym)
			  (let ((slot-fun (intern (concat "STATUS-" (symbol-name slot-sym))
						  (find-package 'mpcl))))
			    `(,slot-sym (,slot-fun ,status))))
		      slots))
       ,@body)))

(defun play-song (song)
  "Switch to a new song. SONG can be either an integer, indicating the
position in the playlist of the song to be played, or a SONG structure
instance (as received from the PLAYLIST function, for example),
reflecting the song to be played."
  (etypecase song
    (song (mpd-command "playid" (song-id song)))
    (integer (mpd-command "play" song))))

(defun next ()
  "Go to the next song in the playlist."
  (mpd-command "next"))

(defun prev ()
  "Go to the previous song in the playlist."
  (mpd-command "previous"))

(defun toggle-pause ()
  "Toggle between the :PAUSE and :PLAY states. Has no effect if the
MPD is in the :STOP state."
  (mpd-command "pause"))

(defun pause ()
  "Pause the playback, but only in the :PLAY state."
  (if (eq (status-state (status)) :play)
      (toggle-pause)))

(defun ping ()
  "Ping the MPD, so as to keep connection open."
  (mpd-command "ping"))

(defun maybe-ping ()
  "Ping the MPD, but only if more than 10 seconds have elapsed since a
command was last sent to it."
  (if (and *socket*
	   (> (- (get-universal-time) *last-command*) 10))
      (progn (ping) t)
      nil))

(defun stop ()
  "Stop playback."
  (mpd-command "stop"))

(defun play ()
  "Start playback of the current song."
  (mpd-command "play"))

(defun current-song ()
  "Returns a SONG structure instance reflecting the currently playing song."
  (first (song-list (mpd-command "currentsong"))))

(defun song-info (song-num)
  "Returns a SONG structure instance describing the song with the
number SONG-NUM in the playlist"
  (declare (type (integer 0 *) song-num))
  (first (song-list (mpd-command "playlistinfo" song-num))))

(defun playlist ()
  "Return a list of SONG structure instances, reflecting the songs in
the current playlist."
  (song-list (mpd-command "playlistinfo")))

(defun search-song (type datum)
  "Search the entire song database for songs matching DATUM. TYPE
specifies what data to search among, and can be one of the following
symbols:

  :ARTIST
  :ALBUM
  :TITLE
  :TRACK
  :GENRE
  :COMPOSER
  :PERFORMER
  :COMMENT

This function returns a list of SONG instances describing the search
results, but meaningful information in the ID and POS slots, whether
or not the songs are actually part of the current playlist."
  (song-list (mpd-command "search" (string-downcase (symbol-name type)) datum)))

(defun search-playlist (type datum)
  "Works like the SEARCH-SONG function, but limits the search to the
currently loaded playlist, and will return meaningful ID and POS
information. See the documentation for the SEARCH-SONG function for
further information."
  (song-list (mpd-command "playlistsearch" (string-downcase (symbol-name type)) datum)))

(defun seek (sec &optional relative)
  "Seek in the currently playing song. If RELATIVE is NIL (the
default), seeks to SEC seconds from the start; otherwise, seeks to SEC
seconds from the current position (may be negative)."
  (with-status (songid pos)
    (if relative
	(setf sec (+ pos sec)))
    (mpd-command "seekid" songid sec)))

(defun set-volume (value &optional relative)
  "Tells the MPD to change the audio system volume to VALUE, ranging
from 0 to 100. If RELATIVE is non-NIL, change the current volume by
VALUE (which may be negative) instead."
  (mpd-command "setvol"
	       (clipnum (if relative
			    (with-status (volume)
			      (+ volume value))
			    value)
			0 100)))

(export '(current-song song-info playlist status with-status ping maybe-ping
	  play-song next prev toggle-pause pause play stop seek set-volume
	  search-song search-playlist))
(provide :mpcl)
