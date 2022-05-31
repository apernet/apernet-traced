%{
    #include <arpa/inet.h>
    #include "config.tab.h"
%}

%option noyywrap
%option nounput
%option noinput
%option yylineno

%%
[ \t\n] {}

rule {
    return RULE;
}

from {
    return FROM;
}

to {
    return TO;
}

hop {
    return HOP;
}

label {
    return LABEL;
}

exp {
    return EXP;
}

s {
    return S;
}

ttl {
    return TTL;
}

([0-9]{1,3}\.){3}[0-9]{1,3} {
    yylval.u32 = inet_addr(yytext);
    return IP;
}

[0-9]+ {
    yylval.u32 = atoi(yytext);
    return NUMBER;
}

random_ip {
    return RANDOM_IP;
}

random_uint {
    return RANDOM_UINT;
}

\$src {
    return SRC;
}

\$dst {
    return DST;
}

\/ {
    return SLASH;
}

\{ {
    return LBRACE;
}

\} {
    return RBRACE;
}

\; {
    return SEMICOLON;
}

\( {
    return LPAREN;
}

\) {
    return RPAREN;
}

, {
    return COMMA;
}

%%