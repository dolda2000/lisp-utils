(defsystem :common-net
  :serial t
  :depends-on (:charcode)
  :components ((:file "common-net")
	       #+sbcl (:file "net-sbcl")
	       #+ecl (:file "net-ecl")
	       #+(or sbcl ecl) (:file "net-sb-bsd")	          ; ECL uses SB-BSD-SOCKETS
	       #+abcl (:file "net-abcl")
	       #+clisp (:file "net-clisp")))
