" Vim syntax file
" Language: gmid(1) configuration files
" Licence: ISC

if exists("b:current_syntax")
  finish
endif

" Syntax Definition: {{{1
" ==================
syn case match
setlocal iskeyword+=-

" Value Types: {{{2
" ============
syn keyword gmidBoolean on contained
syn keyword gmidBoolean off contained

syn match   gmidNumber "\<\d\+\>" display

syn region  gmidQuotedString start=+"+ end=+"+ skip=+\\"+
syn region  gmidQuotedString start=+'+ end=+'+ skip=+\\'+

syn match   gmidVariable "\$\w\w*" display
syn match   gmidMacro    "@\w\w*" display

" Errors: {{{2
" ============
" TODO: write comprehensive syntax rules so it can be checked with:
" syn match gmidError '.'
syn keyword gmidDirectiveDeprecated mime

" Comments: {{{2
" =========
syn match gmidComment "\s*#.*$" display

" Global Options: {{{2
" ===============
syn keyword gmidDirective chroot
syn keyword gmidDirective include
syn keyword gmidDirective ipv6      nextgroup=gmidBoolean skipwhite
syn keyword gmidDirective map
syn keyword gmidDirectiveContinuation to-ext
syn keyword gmidDirective port      nextgroup=gmidNumber  skipwhite
syn keyword gmidDirective prefork   nextgroup=gmidNumber  skipwhite
syn keyword gmidDirective protocols
syn keyword gmidDirective user

" Server Blocks: {{{2
" ==============
syn region gmidBlock start="{" end="}" fold transparent

syn keyword gmidDirectiveBlock server
syn keyword gmidDirectiveBlock location

syn keyword gmidDirective alias
syn match   gmidDirective "\<auto\s\+index\>" nextgroup=gmidBoolean skipwhite display
syn keyword gmidDirective block
syn keyword gmidDirectiveContinuation return nextgroup=gmidNumber skipwhite
syn keyword gmidDirective cert
syn keyword gmidDirective cgi
syn match   gmidDirective "\<default\s\+type>" display
syn keyword gmidDirective entrypoint
syn keyword gmidDirective env
syn keyword gmidDirective fastcgi
syn keyword gmidDirectiveContinuation tcp
syn keyword gmidDirective index
syn keyword gmidDirective key
syn keyword gmidDirective lang
syn keyword gmidDirective log nextgroup=gmidBoolean skipwhite
syn keyword gmidDirective param
syn keyword gmidDirective ocsp
syn keyword gmidDirective root
syn match   gmidDirective "\<require\s\+client\s\+ca\>" display
syn keyword gmidDirective strip nextgroup=gmidNumber skipwhite

" Proxy Blocks: {{{3
" =============
syn keyword gmidDirectiveBlock proxy
syn keyword gmidDirectiveContinuation proto
syn keyword gmidDirectiveContinuation for-host

syn keyword gmidDirective relay-to
syn keyword gmidDirective sni
syn keyword gmidDirective use-tls    nextgroup=gmidBoolean skipwhite
syn keyword gmidDirective verifyname nextgroup=gmidBoolean skipwhite

" Highlighting Settings: {{{1
" ======================

hi def link gmidComment               Comment

hi def link gmidBoolean               Boolean
hi def link gmidNumber                Number
hi def link gmidQuotedString          String

hi def link gmidVariable              Identifier
hi def link gmidMacro                 Macro

hi def link gmidDirective             Keyword
hi def link gmidDirectiveBlock        Function
hi def link gmidDirectiveContinuation Type
hi def link gmidDirectiveDeprecated   Error

let b:current_syntax = "gmid"
