%{
    #include <stdio.h>
    #include <stdint.h>
    #include "log.h"
    #include "trace.h"

    extern int yylineno;
    extern int yylex();
    extern FILE *yyin;

    static int _retval;
    static rule_t *_rules;
    static const char *_filename;

    static void yyerror(const char *s);
%}

%locations
%define parse.error verbose

%union {
    uint32_t u32;
    uint8_t u8;
}

%token SLASH
%token LBRACE
%token RBRACE
%token SEMICOLON

%token RULE
%token FROM
%token TO
%token RANDOM
%token HOP
%token SRC
%token DST
%token LABEL
%token EXP
%token S
%token TTL

%token <u32> IP
%token <u32> NUMBER

%%
rule_list: rule | rule_list rule

rule: RULE selectors LBRACE hop_list RBRACE

selectors
    : FROM IP SLASH NUMBER
    | TO IP SLASH NUMBER
    | FROM IP SLASH NUMBER TO IP SLASH NUMBER

hop_list: hop | hop_list hop

hop
    : HOP hop_spec LBRACE label_list RBRACE
    | HOP hop_spec SEMICOLON

hop_spec: IP | RANDOM | SRC | DST

label_list: label | label_list label

label
    : LABEL NUMBER LBRACE label_options RBRACE
    | LABEL RANDOM LBRACE label_options RBRACE

label_options: label_option | label_options label_option

label_option
    : TTL label_val SEMICOLON
    | EXP label_val SEMICOLON
    | S label_val SEMICOLON

label_val: NUMBER | RANDOM

%%
int parse_rules(const char *filename, rule_t **rules) {
    _filename = filename;
    _rules = (rule_t *) malloc(sizeof(rule_t));
    _retval = 0;

    *rules = _rules;

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_error("failed to open config file %s", filename);
        return -1;
    }

    yyin = f;
    yylineno = 1;
    yyparse();
    fclose(f);

    return _retval;
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    _retval = -1;
}