;;;; redos-spotter command line.
(load (merge-pathnames "redos.lisp" (or *load-truename* *default-pathname-defaults*)))
(in-package :redos)

(defun usage ()
  (format *error-output* "usage: redos-spotter PATTERNS_FILE [--tsv] [--fail-on high|medium]~%Exit: 0 ok, 1 findings at or above --fail-on, 2 bad input.~%")
  (finish-output *error-output*)
  (sb-ext:exit :code 2 :abort t))

(defun sev-rank (s) (ecase s (:high 0) (:medium 1) (:info 2)))
(defun sev-name (s) (string-downcase (symbol-name s)))

(defun read-patterns (file)
  (with-open-file (in file :external-format :latin-1)
    (loop for line = (read-line in nil) for n from 1 while line
          for tr = (string-right-trim '(#\Return) line)
          unless (or (zerop (length tr)) (char= (char tr 0) #\#))
            collect (cons n tr))))

(defun main (args)
  (let ((file nil) (tsv nil) (fail nil))
    (loop while args
          do (let ((a (pop args)))
               (cond ((string= a "--tsv") (setf tsv t))
                     ((and (string= a "--fail-on") args)
                      (let ((v (pop args)))
                        (cond ((string= v "high") (setf fail :high)) ((string= v "medium") (setf fail :medium)) (t (usage)))))
                     ((and (plusp (length a)) (char= (char a 0) #\-)) (usage))
                     (file (usage))
                     (t (setf file a)))))
    (unless file (usage))
    (unless (probe-file file)
      (format *error-output* "error: no such file: ~a~%" file) (finish-output *error-output*)
      (sb-ext:exit :code 2 :abort t))
    (let* ((patterns (read-patterns file)) (rows '()) (clean 0))
      (dolist (p patterns)
        (let ((fs (analyse-pattern (cdr p))))
          (if fs
              (dolist (f fs) (push (list (finding-severity f) (finding-rule f) (format nil "line ~d: ~a" (car p) (cdr p)) (finding-message f)) rows))
              (incf clean))))
      (setf rows (stable-sort (nreverse rows) #'< :key (lambda (r) (sev-rank (first r)))))
      (let ((risky (count-if (lambda (r) (member (first r) '(:high :medium))) rows)))
        (if tsv
            (format t "# ~d patterns, ~d clean, ~d findings~%" (length patterns) clean (length rows))
            (format t "~d patterns, ~d clean, ~d findings~%" (length patterns) clean (length rows)))
        (dolist (r rows)
          (if tsv
              (format t "~a~c~a~c~a~c~a~%" (sev-name (first r)) #\Tab (second r) #\Tab (third r) #\Tab (fourth r))
              (format t "~a ~a ~a~%          ~a~%" (string-upcase (sev-name (first r))) (second r) (third r) (fourth r))))
        (finish-output)
        (sb-ext:exit :code (cond ((null fail) 0)
                                 ((eq fail :high) (if (find :high rows :key #'first) 1 0))
                                 (t (if (plusp risky) 1 0)))
                     :abort t)))))

(main (cdr sb-ext:*posix-argv*))
