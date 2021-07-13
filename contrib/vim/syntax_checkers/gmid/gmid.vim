" Syntax checking plugin for syntastic
" Language: gmid(1) configuration file
" Licence: ISC

if exists('g:loaded_syntastic_gmid_gmid_checker')
    finish
endif
let g:loaded_syntastic_gmid_gmid_checker = 1

let s:save_cpo = &cpo
set cpo&vim

function! SyntaxCheckers_gmid_gmid_GetLocList() dict
    let makeprg = self.makeprgBuild({ 'args': '-nc' })

    let errorformat =
        \ '%-Gconfig OK,' .
        \ '%f:%l %tarning: %m,' .
        \ '%f:%l %trror: %m'

    return SyntasticMake({
        \ 'makeprg': makeprg,
        \ 'errorformat': errorformat,
        \ 'defaults': {'type': 'E'},
        \ 'returns': [0, 1] })
endfunction

call g:SyntasticRegistry.CreateAndRegisterChecker({
    \ 'filetype': 'gmid',
    \ 'name': 'gmid',
    \ 'exec': 'gmid'})

let &cpo = s:save_cpo
unlet s:save_cpo

" vim: set sw=4 sts=4 et fdm=marker:
