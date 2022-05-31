%{
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
    return IP;
}

[0-9]+ {
    return NUMBER;
}

\$random {
    return RANDOM;
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

%%