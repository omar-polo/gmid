" Vim filetype detection file
" Language: gmid(1) configuration files
" Licence: ISC

au BufNewFile,BufRead *.gmid       set filetype=gmid
au BufNewFile,BufRead */etc/gmid/* set filetype=gmid
au BufNewFile,BufRead gmid.conf    set filetype=gmid
