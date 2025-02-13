# To generate the documentation, run
rst2html5 -d --stylesheet-path=minimal.css,plain.css,theme.css index.rst > index.html

# Note that there are several different versions of rst2html5. (Notably, pip ships a version that behaves slightly
# differently. We use the Ubuntu Bionic version provided by the `python3-docutils` package:
#
#    apt install python3-docutils
