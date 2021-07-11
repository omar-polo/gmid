if exists("b:did_ftplugin")
  finish
endif
let b:did_ftplugin = 1
let b:undo_ftplugin = "setl cms< sua<"

setlocal suffixesadd+=.conf,.gmid

" vim-commentary support
setlocal commentstring=#\ %s
