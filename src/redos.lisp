;;;; redos-spotter core: regex parser, ambiguity analysis and a step-counting backtracking probe.
(defpackage :redos
  (:use :cl)
  (:export #:parse-regex #:analyse #:probe #:node-first #:node-last #:nullable-p
           #:mask-of-chars #:mask-members #:analyse-pattern #:finding-severity #:finding-rule
           #:finding-message #:match-steps))
(in-package :redos)

;;; Character sets are integers used as 256-bit masks.
(defconstant +all+ (1- (ash 1 256)))
(defun bit-mask (code) (ash 1 code))
(defun mask-of-chars (string) (let ((m 0)) (loop for c across string do (setf m (logior m (bit-mask (char-code c))))) m))
(defun range-mask (lo hi) (let ((m 0)) (loop for c from lo to hi do (setf m (logior m (bit-mask c)))) m))
(defparameter +digit+ (range-mask 48 57))
(defparameter +word+ (logior (range-mask 48 57) (range-mask 65 90) (range-mask 97 122) (bit-mask 95)))
(defparameter +space+ (mask-of-chars (coerce '(#\Space #\Tab #\Newline #\Return #\Page #\Vt) 'string)))
(defparameter +dot+ (logandc2 +all+ (bit-mask 10)))
(defun mask-members (m) (loop for c from 0 below 256 when (logbitp c m) collect c))

(define-condition unsupported (error) ((what :initarg :what :reader what)))
(define-condition bad-pattern (error) ((what :initarg :what :reader what)))

;;; AST: (:set mask) (:seq . items) (:alt . branches) (:rep min max node possessive) (:empty)

(defvar *s*) (defvar *i*)
(defun peek () (and (< *i* (length *s*)) (char *s* *i*)))
(defun next () (prog1 (char *s* *i*) (incf *i*)))
(defun eat (c) (when (eql (peek) c) (incf *i*) t))

(defun parse-regex (string)
  (let ((*s* string) (*i* 0))
    (let ((node (parse-alt)))
      (when (< *i* (length *s*)) (error 'bad-pattern :what "unbalanced )"))
      node)))

(defun parse-alt ()
  (let ((branches (list (parse-seq))))
    (loop while (eat #\|) do (push (parse-seq) branches))
    (if (cdr branches) (cons :alt (nreverse branches)) (car branches))))

(defun parse-seq ()
  (let ((items '()))
    (loop for c = (peek)
          while (and c (not (member c '(#\| #\)))))
          do (push (parse-quantified) items))
    (if (and items (null (cdr items))) (car items) (cons :seq (nreverse items)))))

(defun parse-quantified ()
  (let ((atom (parse-atom)))
    (loop
      (let ((c (peek)) (min nil) (max nil))
        (cond ((eql c #\*) (next) (setf min 0 max nil))
              ((eql c #\+) (next) (setf min 1 max nil))
              ((eql c #\?) (next) (setf min 0 max 1))
              ((eql c #\{)
               (let ((save *i*))
                 (next)
                 (multiple-value-bind (ok lo hi) (parse-braces)
                   (if ok (setf min lo max hi) (progn (setf *i* save) (return atom))))))
              (t (return atom)))
        (when (and (not (eql c #\{)) nil) nil)
        (let ((possessive nil))
          (cond ((eat #\?) nil)
                ((eat #\+) (setf possessive t)))
          (setf atom (list :rep min max atom possessive)))))))

(defun parse-braces ()
  ;; after '{': n} | n,} | n,m}
  (let ((lo nil) (hi nil) (start *i*))
    (flet ((num () (let ((st *i*)) (loop while (and (peek) (digit-char-p (peek))) do (next))
                     (and (> *i* st) (parse-integer *s* :start st :end *i*)))))
      (setf lo (num))
      (unless lo (setf *i* start) (return-from parse-braces nil))
      (cond ((eat #\}) (values t lo lo))
            ((eat #\,)
             (setf hi (num))
             (if (eat #\}) (values t lo hi) (progn (setf *i* start) nil)))
            (t (setf *i* start) nil)))))

(defun parse-atom ()
  (let ((c (next)))
    (case c
      (#\( (parse-group))
      (#\[ (parse-class))
      (#\. (list :set +dot+))
      ((#\^ #\$) (list :empty))
      (#\\ (parse-escape nil))
      ((#\* #\+ #\?) (error 'bad-pattern :what "nothing to repeat"))
      (t (list :set (bit-mask (min 255 (char-code c))))))))

(defun parse-group ()
  (let ((possessive nil))
    (when (eql (peek) #\?)
      (next)
      (let ((k (next)))
        (case k
          (#\: nil)
          (#\> (setf possessive t))
          (#\P (error 'unsupported :what "named group syntax"))
          (#\< (if (member (peek) '(#\= #\!))
                   (progn (next) (let ((n (parse-alt))) (declare (ignore n)) (unless (eat #\)) (error 'bad-pattern :what "unbalanced (")) (return-from parse-group (list :empty))))
                   (loop until (eql (next) #\>))))
          ((#\= #\!) (error 'unsupported :what "lookahead"))
          (t (error 'unsupported :what (format nil "group flag ~a" k))))))
    (let ((inner (parse-alt)))
      (unless (eat #\)) (error 'bad-pattern :what "unbalanced ("))
      (if possessive (list :rep 1 1 inner t) inner))))

(defun class-escape (c)
  (case c
    (#\d +digit+) (#\D (logandc2 +all+ +digit+))
    (#\w +word+) (#\W (logandc2 +all+ +word+))
    (#\s +space+) (#\S (logandc2 +all+ +space+))
    (#\n (bit-mask 10)) (#\t (bit-mask 9)) (#\r (bit-mask 13)) (#\f (bit-mask 12)) (#\v (bit-mask 11))
    (t nil)))

(defun parse-escape (in-class)
  (unless (peek) (error 'bad-pattern :what "trailing backslash"))
  (let ((c (next)))
    (cond ((class-escape c) (list :set (class-escape c)))
          ((and (not in-class) (member c '(#\b #\B #\A #\Z #\z))) (list :empty))
          ((and (not in-class) (digit-char-p c) (char/= c #\0)) (error 'unsupported :what "backreference"))
          ((eql c #\x)
           (let ((h (parse-integer *s* :start *i* :end (min (length *s*) (+ *i* 2)) :radix 16 :junk-allowed t)))
             (unless h (error 'bad-pattern :what "bad \\x escape"))
             (incf *i* 2) (list :set (bit-mask (min 255 h)))))
          (t (list :set (bit-mask (min 255 (char-code c))))))))

(defun parse-class ()
  (let ((negate (eat #\^)) (m 0) (first t))
    (loop
      (let ((c (peek)))
        (unless c (error 'bad-pattern :what "unterminated ["))
        (when (and (eql c #\]) (not first)) (next) (return))
        (setf first nil)
        (next)
        (let ((lo (if (eql c #\\) (let ((e (parse-escape t))) (second e)) (bit-mask (min 255 (char-code c))))))
          (if (and (eql (peek) #\-) (< (1+ *i*) (length *s*)) (not (eql (char *s* (1+ *i*)) #\]))
                   (= (logcount lo) 1))
              (progn (next)
                     (let* ((c2 (next))
                            (hi (if (eql c2 #\\) (second (parse-escape t)) (bit-mask (min 255 (char-code c2))))))
                       (setf m (logior m (range-mask (1- (integer-length lo)) (1- (integer-length hi)))))))
              (setf m (logior m lo))))))
    (list :set (if negate (logandc2 +all+ m) m))))

;;; Language properties

(defun nullable-p (n)
  (ecase (car n)
    (:set nil) (:empty t)
    (:seq (every #'nullable-p (cdr n)))
    (:alt (some #'nullable-p (cdr n)))
    (:rep (or (zerop (second n)) (nullable-p (fourth n))))))

(defun node-first (n)
  (ecase (car n)
    (:set (second n)) (:empty 0)
    (:seq (let ((m 0)) (dolist (x (cdr n) m) (setf m (logior m (node-first x))) (unless (nullable-p x) (return m)))))
    (:alt (reduce #'logior (mapcar #'node-first (cdr n)) :initial-value 0))
    (:rep (node-first (fourth n)))))

(defun node-last (n)
  (ecase (car n)
    (:set (second n)) (:empty 0)
    (:seq (let ((m 0)) (dolist (x (reverse (cdr n)) m) (setf m (logior m (node-last x))) (unless (nullable-p x) (return m)))))
    (:alt (reduce #'logior (mapcar #'node-last (cdr n)) :initial-value 0))
    (:rep (node-last (fourth n)))))

(defun node-chars (n)
  (ecase (car n)
    (:set (second n)) (:empty 0)
    ((:seq :alt) (reduce #'logior (mapcar #'node-chars (cdr n)) :initial-value 0))
    (:rep (node-chars (fourth n)))))

(defun unbounded-p (n) (and (eq (car n) :rep) (null (third n)) (not (fifth n))))

;;; Loops that can sit at the head or tail of a node: list of masks.
(defun tail-loops (n)
  (ecase (car n)
    ((:set :empty) '())
    (:seq (let ((acc '())) (dolist (x (reverse (cdr n)) acc) (setf acc (append acc (tail-loops x))) (unless (nullable-p x) (return acc)))))
    (:alt (mapcan #'tail-loops (copy-list (cdr n))))
    (:rep (if (fifth n) '()
              (append (when (null (third n)) (list (node-chars (fourth n)))) (tail-loops (fourth n)))))))
(defun head-loops (n)
  (ecase (car n)
    ((:set :empty) '())
    (:seq (let ((acc '())) (dolist (x (cdr n) acc) (setf acc (append acc (head-loops x))) (unless (nullable-p x) (return acc)))))
    (:alt (mapcan #'head-loops (copy-list (cdr n))))
    (:rep (if (fifth n) '()
              (append (when (null (third n)) (list (node-chars (fourth n)))) (head-loops (fourth n)))))))

(defun contains-unbounded-p (n)
  (case (car n)
    (:rep (or (unbounded-p n) (and (not (fifth n)) (contains-unbounded-p (fourth n)))))
    ((:seq :alt) (some #'contains-unbounded-p (cdr n)))
    (t nil)))

;;; Findings: (severity rule message witness-mask)
(defstruct (finding (:conc-name finding-)) severity rule message witness)

(defun unwrap (n) (if (and (eq (car n) :seq) (cdr n) (null (cddr n))) (unwrap (second n)) n))

(defun nested-witness (body)
  "Mask of characters that make the loop ambiguous, or NIL."
  (let ((f (node-first body)) (l (node-last body)) (w 0))
    (dolist (m (tail-loops body)) (setf w (logior w (logand f m))))
    (dolist (m (head-loops body)) (setf w (logior w (logand l m))))
    (and (plusp w) w)))

(defun alt-overlap (alt)
  (let ((branches (mapcar #'unwrap (cdr alt))))
    (loop for (a . rest) on branches
          do (dolist (b rest)
               (let ((ia (items-of a)) (ib (items-of b)))
                 (when (and (= (length ia) (length ib)) (plusp (length ia))
                            (every (lambda (x y) (plusp (logand (node-chars x) (node-chars y)))) ia ib)
                            (every (lambda (x) (member (car x) '(:set))) (append ia ib)))
                   (return-from alt-overlap (reduce #'logand (mapcar (lambda (x y) (logand (node-chars x) (node-chars y))) ia ib)
                                                    :initial-value +all+))))))
    nil))
(defun items-of (n) (if (eq (car n) :seq) (cdr n) (list n)))

(defun simple-loop-p (n)
  (and (unbounded-p n) (eq (car (unwrap (fourth n))) :set)))

(defun walk (n fn)
  (funcall fn n)
  (case (car n)
    ((:seq :alt) (dolist (x (cdr n)) (walk x fn)))
    (:rep (walk (fourth n) fn))))

(defun loop-findings (n)
  (let ((out '()))
    (when (unbounded-p n)
      (let ((body (unwrap (fourth n))))
        (when (contains-unbounded-p body)
          (let ((w (nested-witness body)))
            (when w
              (push (make-finding :severity :high :rule "REDOS001"
                                  :message "nested quantifiers: the same text can be split between iterations in many ways"
                                  :witness w)
                    out))))
        (when (eq (car body) :alt)
          (let ((w (alt-overlap body)))
            (when w
              (push (make-finding :severity :high :rule "REDOS002"
                                  :message "alternation inside a loop with overlapping branches"
                                  :witness w)
                    out))))))
    out))

(defun chain-finding (n)
  "Adjacent simple loops over overlapping characters inside a sequence."
  (let ((run '()) (best nil) (best-len 1))
    (flet ((flush ()
             (when (> (length run) best-len) (setf best-len (length run) best (reverse run)))
             (setf run '())))
      (dolist (x (cdr n))
        (cond ((simple-loop-p x)
               (if (and run (plusp (logand (node-chars (car run)) (node-chars x))))
                   (push x run)
                   (progn (flush) (setf run (list x)))))
              ((and (eq (car x) :rep) (nullable-p x) (not (unbounded-p x))) nil)
              (t (flush))))
      (flush))
    (when (>= best-len 2)
      (let ((w (reduce #'logand (mapcar #'node-chars best))))
        (make-finding :severity (if (>= best-len 3) :high :medium) :rule "REDOS003"
                      :message (format nil "~d adjacent loops over overlapping characters: ~a time on failing input"
                                       best-len (case best-len (2 "quadratic") (3 "cubic") (t "polynomial")))
                      :witness (if (plusp w) w (node-chars (car best))))))))

(defun analyse (ast)
  (let ((out '()))
    (walk ast
          (lambda (n)
            (setf out (append out (loop-findings n)))
            (when (eq (car n) :seq)
              (let ((f (chain-finding n))) (when f (setf out (append out (list f))))))))
    out))

;;; Step-counting backtracking probe (full match).
(defvar *steps*) (defvar *limit*)
(defun match-steps (ast string &optional (limit 2000000))
  "Returns (values steps matched-p exceeded-p). A full match is attempted."
  (let ((*steps* 0) (*limit* limit) (len (length string)))
    (labels ((m (n i k)
               (ecase (car n)
                 (:empty (funcall k i))
                 (:set (when (< i len)
                         (when (> (incf *steps*) *limit*) (throw 'budget :exceeded))
                         (and (logbitp (min 255 (char-code (char string i))) (second n)) (funcall k (1+ i)))))
                 (:seq (ms (cdr n) i k))
                 (:alt (some (lambda (b) (m b i k)) (cdr n)))
                 (:rep (destructuring-bind (min max body poss) (cdr n)
                         (declare (ignore poss))
                         (labels ((try (count i)
                                    (or (and (or (null max) (< count max))
                                             (m body i (lambda (j) (and (or (> j i) (< count min)) (try (1+ count) j)))))
                                        (and (>= count min) (funcall k i)))))
                           (try 0 i))))))
             (ms (items i k) (if (null items) (funcall k i) (m (car items) i (lambda (j) (ms (cdr items) j k))))))
      (let ((r (catch 'budget (m ast 0 (lambda (j) (= j len))))))
        (if (eq r :exceeded) (values *steps* nil t) (values *steps* (and r t) nil))))))

(defun pick-char (mask)
  (let ((codes (mask-members mask)))
    (code-char (or (find-if (lambda (c) (<= 97 c 122)) codes) (find-if (lambda (c) (<= 33 c 126)) codes) (car codes) 97))))

(defun attack (witness n suffix) (concatenate 'string (make-string n :initial-element (pick-char witness)) (string suffix)))

(defun probe (ast witness polynomial-p)
  "Returns (values confirmed-p description)."
  (let* ((small (if polynomial-p 30 10)) (large (if polynomial-p 60 20)) (best nil))
    (dolist (suffix (list #\! #\~ #\Newline #\# #\Space #\@))
      (multiple-value-bind (s1 m1 e1) (match-steps ast (attack witness small suffix))
        (declare (ignore m1 e1))
        (multiple-value-bind (s2 m2 e2) (match-steps ast (attack witness large suffix))
          (declare (ignore m2))
          (let ((ratio (/ (max s2 1) (max s1 1))))
            (when (or (null best) (> ratio (first best))) (setf best (list ratio s1 s2 e2)))))))
    (destructuring-bind (ratio s1 s2 exceeded) best
      (let ((confirmed (if polynomial-p (>= ratio 3) (>= ratio 20))))
        (values confirmed
                (format nil "~a: ~d steps on ~d chars, ~a~d steps on ~d chars"
                        (if confirmed "confirmed" "not confirmed") s1 small (if exceeded ">" "") (if exceeded 2000000 s2) large))))))

(defun analyse-pattern (pattern)
  "Returns a list of findings with evidence appended to messages."
  (handler-case
      (let* ((ast (parse-regex pattern)) (fs (analyse ast)))
        (dolist (f fs)
          (multiple-value-bind (ok desc) (probe ast (finding-witness f) (string= (finding-rule f) "REDOS003"))
            (declare (ignore ok))
            (setf (finding-message f) (format nil "~a (~a)" (finding-message f) desc))))
        fs)
    (unsupported (e) (list (make-finding :severity :info :rule "REDOS000" :message (format nil "not analysed: ~a is not modelled" (what e)))))
    (bad-pattern (e) (list (make-finding :severity :info :rule "REDOS000" :message (format nil "not analysed: ~a" (what e)))))))
