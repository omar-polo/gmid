" Linter for ALE
" Language: gmid(1) configuration file
" Licence: ISC

call ale#Set('gmid_executable', 'gmid')

function! ale_linters#gmid#gmid#Handle(buffer, lines) abort
    let l:output = []
    let l:gmid_type_to_ale_type = {
    \    'error': 'E',
    \    'warning': 'W',
    \}

    let l:pattern = '\v^(.*):(\d*) ([a-z]+): (.*)$'
    for l:match in ale#util#GetMatches(a:lines, l:pattern)
        call add(l:output, {
	\   'filename': l:match[1],
        \   'lnum': l:match[2],
        \   'type': get(l:gmid_type_to_ale_type, l:match[3], 'E'),
        \   'text': l:match[4],
        \})
    endfor

    return l:output
endfunction

call ale#linter#Define('gmid', {
\    'name': 'gmid',
\    'executable': {buffer -> ale#Var(buffer, 'gmid_executable')},
\    'command': '%e -nc %s',
\    'output_stream': 'both',
\    'lint_file': 1,
\    'callback': 'ale_linters#gmid#gmid#Handle',
\})

" vim: set sw=4 sts=4 et fdm=marker:
