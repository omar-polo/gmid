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
syn keyword gmidBoolean on  contained
syn keyword gmidBoolean off contained

syn match   gmidNumber "\<\d\+\>" display

syn keyword gmidStyle common   contained
syn keyword gmidStyle combined contained
syn keyword gmidStyle legacy   contained

syn keyword gmidFacility daemon contained
syn keyword gmidFacility ftp    contained
syn keyword gmidFacility local0 contained
syn keyword gmidFacility local1 contained
syn keyword gmidFacility local2 contained
syn keyword gmidFacility local3 contained
syn keyword gmidFacility local4 contained
syn keyword gmidFacility local5 contained
syn keyword gmidFacility local6 contained
syn keyword gmidFacility local7 contained
syn keyword gmidFacility user   contained

syn region  gmidQuotedString start=+"+ end=+"+ skip=+\\"+
syn region  gmidQuotedString start=+'+ end=+'+ skip=+\\'+

syn match   gmidVariable "\$\w\w*" display
syn match   gmidMacro    "@\w\w*"  display

syn cluster gmidValues contains=gmidNumber,
\                               gmidQuotedString,
\                               gmidVariable,
\                               gmidMacro,
\                               gmidDeprecated

" Errors: {{{2
" ============
" TODO: write comprehensive syntax rules so it can be checked with:
" syn match gmidError '.'
syn keyword gmidDeprecated ipv6 nextgroup=gmidBoolean skipwhite

" Comments: {{{2
" =========
syn match gmidComment "\s*#.*$" display

" Global Options: {{{2
" ===============
syn keyword gmidDirective chroot
syn keyword gmidDirective include
syn keyword gmidDirective prefork nextgroup=gmidNumber skipwhite
syn keyword gmidDirective protocols
syn keyword gmidDirective user

" Logging options
syn match   gmidDirective "\<log\s\+access\>" display
syn match   gmidDirective "\<log\s\+style\>" display
\                         nextgroup=gmidStyle skipwhite
syn match   gmidDirective "\<log\s\+syslog\>" display
\                         nextgroup=gmidBoolean skipwhite 
syn match   gmidDirective "\<log\s\+syslog\s\+facility\>" display
\                         nextgroup=gmidFacility skipwhite

" Global Log Blocks: {{{3
" ==================
syn region  gmidBlockLog start="log\s\+{" end="}"
\                        fold transparent
\                        contains=gmidDirectiveLog,
\                                 @gmidValues
syn keyword gmidDirectiveBlock log contained containedin=gmidBlockLog

syn keyword gmidDirectiveLog access contained
syn keyword gmidDirectiveLog style  contained nextgroup=gmidStyle skipwhite
syn keyword gmidDirectiveLog syslog contained nextgroup=gmidBoolean skipwhite
syn match   gmidDirectiveLog "\<syslog\s\+facility\>" display
\                                   contained nextgroup=gmidFacility skipwhite

" Server Blocks: {{{2
" ==============
syn region  gmidBlockServer start="server\s\+.\+\s\+{" end="}"
\                           fold transparent
\                           contains=gmidDirectiveServer,
\                                    gmidDirectiveParamServer,
\                                    gmidDirectiveHost,
\                                    gmidDirectiveParamHost,
\                                    gmidBlockLocation,
\                                    gmidBlockFastcgi,
\                                    gmidBlockProxy,
\                                    @gmidValues
syn keyword gmidDirectiveBlock server contained containedin=gmidBlockServer

syn region  gmidBlockLocation start="location\s\+.\+\s\+{" end="}"
\                             fold transparent contained
\                             contains=gmidDirectiveHost,
\                                      gmidDirectiveParamHost,
\                                      gmidBlockFastcgi,
\                                      @gmidValues
syn keyword gmidDirectiveBlock location contained containedin=gmidBlockLocation

syn match   gmidDirectiveHost "\<auto\s\+index\>" display
\                                   contained nextgroup=gmidBoolean skipwhite
syn keyword gmidDirectiveHost block contained
syn keyword gmidDirectiveParamHost return contained nextgroup=gmidNumber skipwhite
syn match   gmidDirectiveHost "\<default\s\+type\>" display contained
syn keyword gmidDirectiveHost index contained
syn keyword gmidDirectiveHost lang  contained
syn keyword gmidDirectiveHost log   contained nextgroup=gmidBoolean skipwhite
syn keyword gmidDirectiveHost ocsp  contained
syn keyword gmidDirectiveHost root  contained
syn match   gmidDirectiveHost "\<require\s\+client\s\+ca\>" display contained
syn keyword gmidDirectiveHost strip contained nextgroup=gmidNumber skipwhite

" FastCGI options
syn match   gmidDirectiveHost "\<fastcgi\s\+off\>" display contained
syn match   gmidDirectiveHost "\<fastcgi\s\+socket\>" display contained
syn keyword gmidDirectiveParamHost tcp contained
syn match   gmidDirectiveHost "\<fastcgi\s\+strip\>" display
\                                      contained nextgroup=gmidNumber skipwhite

" Options unavailable for `location`
syn keyword gmidDirectiveServer alias contained
syn keyword gmidDirectiveServer cert  contained
syn keyword gmidDirectiveServer key   contained
syn match   gmidDirectiveServer "\<listen\s\+on\>" display contained

" Ambiguos, can be used both in `listen on` and `fastcgi socket`
syn keyword gmidDirectiveParamHost port contained nextgroup=gmidNumber skipwhite

" FastCGI Blocks: {{{3
" ===============
syn region  gmidBlockFastcgi start="fastcgi\s\+{" end="}"
\                            fold transparent contained
\                            contains=gmidDirectiveFastcgi,
\                                     gmidDirectiveParamFastcgi,
\                                     @gmidValues
syn keyword gmidDirectiveBlock fastcgi contained containedin=gmidBlockFastcgi

syn keyword gmidDirectiveFastcgi param  contained
syn keyword gmidDirectiveFastcgi socket contained
syn keyword gmidDirectiveParamFastcgi tcp  contained
syn keyword gmidDirectiveParamFastcgi port contained nextgroup=gmidNumber skipwhite
syn keyword gmidDirectiveFastcgi strip  contained nextgroup=gmidNumber skipwhite

" Proxy Blocks: {{{3
" =============
syn region  gmidBlockProxy start="proxy\s\+\(.*\s\+\)\?{" end="}"
\                          fold transparent contained
\                          contains=gmidDirectiveProxy,
\                                   gmidDirectiveParamProxy,
\                                   @gmidValues
syn keyword gmidDirectiveBlock proxy contained containedin=gmidBlockProxy

syn keyword gmidDirectiveParamProxy proto    contained
syn keyword gmidDirectiveParamProxy for-host contained

syn keyword gmidDirectiveProxy cert       contained
syn keyword gmidDirectiveProxy key        contained
syn keyword gmidDirectiveProxy protocols  contained
syn keyword gmidDirectiveProxy relay-to   contained
syn match   gmidDirectiveProxy "\<require\s\+client\s\+ca\>" display contained
syn keyword gmidDirectiveProxy sni        contained
syn keyword gmidDirectiveProxy use-tls    contained nextgroup=gmidBoolean skipwhite
syn keyword gmidDirectiveProxy verifyname contained nextgroup=gmidBoolean skipwhite

" Ambiguos, can be used both in `proxy` and `relay-to`
syn keyword gmidDirectiveParamProxy port contained nextgroup=gmidNumber skipwhite

" Types Blocks: {{{2
" =============
syn region  gmidBlockTypes start="types\s\+{" end="}"
\                          fold transparent
\                          contains=gmidDirectiveTypes,
\                                   @gmidValues
syn keyword gmidDirectiveBlock types contained containedin=gmidBlockTypes

syn keyword gmidDirectiveTypes include contained

" Highlighting Settings: {{{1
" ======================

" Create aliases

hi def link gmidDirectiveLog          gmidDirective
hi def link gmidDirectiveTypes        gmidDirective

hi def link gmidDirectiveServer       gmidDirective
hi def link gmidDirectiveParamServer  gmidDirectiveParam

hi def link gmidDirectiveHost         gmidDirective
hi def link gmidDirectiveParamHost    gmidDirectiveParam

hi def link gmidDirectiveFastcgi      gmidDirective
hi def link gmidDirectiveParamFastcgi gmidDirectiveParam

hi def link gmidDirectiveProxy        gmidDirective
hi def link gmidDirectiveParamProxy   gmidDirectiveParam

" Map to standard types

hi def link gmidComment               Comment

hi def link gmidBoolean               Boolean
hi def link gmidNumber                Number
hi def link gmidStyle                 Constant
hi def link gmidFacility              Constant
hi def link gmidQuotedString          String

hi def link gmidVariable              Identifier
hi def link gmidMacro                 Macro

hi def link gmidDirective             Keyword
hi def link gmidDirectiveBlock        Function
hi def link gmidDirectiveParam        Type
hi def link gmidDeprecated            Error

let b:current_syntax = "gmid"
