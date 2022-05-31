%{
    #include <stdio.h>
    #include <stdint.h>
    #include <string.h>
    #include <stdlib.h>
    #include "log.h"
    #include "trace.h"

    extern int yylineno;
    extern int yylex();
    extern FILE *yyin;

    static int _retval;
    static rule_t *_rules;
    static const char *_filename;

    static rule_t *_current_rule;
    static hop_t *_current_hops;

    static stack_t *_pending_stack;
    static stack_t *_prev_stack;

    static size_t _current_hop_index;

    #define _current_hop (_current_hops[_current_hop_index])

    static const uint32_t CIDR_MASK_MAP[33] = {
        0x00000000, 0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000,
        0xfc000000, 0xfe000000, 0xff000000, 0xff800000, 0xffc00000, 0xffe00000,
        0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000, 0xffff8000,
        0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,
        0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8,
        0xfffffffc, 0xfffffffe, 0xffffffff
    };

    static void yyerror(const char *s);

    static int new_rule();
    static int new_hop();

    static int save_stack();
    
    static int set_rule_from(uint32_t ip, uint32_t mask);
    static int set_rule_to(uint32_t ip, uint32_t mask);
%}

%locations
%define parse.error verbose

%union {
    uint32_t u32;
}

%token SLASH
%token LBRACE
%token RBRACE
%token SEMICOLON

%token RULE
%token FROM
%token TO
%token RANDOM_IP
%token RANDOM_UINT
%token LPAREN
%token RPAREN
%token COMMA
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
    : FROM IP SLASH NUMBER {
        new_rule();

        if (set_rule_from($2, $4) < 0) {
            YYERROR;
        }
    }
    | TO IP SLASH NUMBER {
        new_rule();

        if (set_rule_to($2, $4) < 0) {
            YYERROR;
        }
    }
    | FROM IP SLASH NUMBER TO IP SLASH NUMBER {
        new_rule();

        if (set_rule_from($2, $4) < 0) {
            YYERROR;
        }

        if (set_rule_to($6, $8) < 0) {
            YYERROR;
        }
    }

hop_list: hop | hop_list hop

hop: HOP hop_src hop_def

hop_src
    : IP {
        if (new_hop() < 0) {
            YYERROR;
        }

        _current_hop.type = HOP_TTPE_LITERAL;
        _current_hop.address = $1;
    }
    | RANDOM_IP LPAREN IP COMMA IP RPAREN {
        if (new_hop() < 0) {
            YYERROR;
        }

        _current_hop.type = HOP_TYPE_RANDOM;
        _current_hop.address_rand_min = $3;
        _current_hop.address_rand_max = $5;
    }
    | SRC {
        if (new_hop() < 0) {
            YYERROR;
        }

        _current_hop.type = HOP_TYPE_SRC;
    }
    | DST {
        if (new_hop() < 0) {
            YYERROR;
        }

        _current_hop.type = HOP_TYPE_DST;
    }

hop_def: LBRACE label_list RBRACE | SEMICOLON

label_list: label | label_list label

label
    : LABEL NUMBER LBRACE label_options RBRACE {
        _pending_stack->label_type = VAL_TYPE_LITERAL;
        _pending_stack->label = $2;

        save_stack();
    }
    | LABEL RANDOM_UINT LPAREN NUMBER COMMA NUMBER RPAREN LBRACE label_options RBRACE {
        _pending_stack->label_type = VAL_TYPE_RANDOM;
        _pending_stack->label_rand_min = $4;
        _pending_stack->label_rand_max = $6;

        save_stack();
    }

label_options: label_option | label_options label_option

label_option
    : TTL NUMBER SEMICOLON {
        _pending_stack->ttl_type = VAL_TYPE_LITERAL;
        _pending_stack->ttl = $2;
    }
    | EXP NUMBER SEMICOLON {
        _pending_stack->exp_type = VAL_TYPE_LITERAL;
        _pending_stack->exp = $2;
    }
    | S NUMBER SEMICOLON {
        _pending_stack->s_type = VAL_TYPE_LITERAL;
        _pending_stack->s = $2;
    }
    | TTL RANDOM_UINT LPAREN NUMBER COMMA NUMBER RPAREN SEMICOLON {
        _pending_stack->ttl_type = VAL_TYPE_RANDOM;
        _pending_stack->ttl_rand_min = $4;
        _pending_stack->ttl_rand_max = $6;
    }
    | EXP RANDOM_UINT LPAREN NUMBER COMMA NUMBER RPAREN SEMICOLON {
        _pending_stack->exp_type = VAL_TYPE_RANDOM;
        _pending_stack->exp_rand_min = $4;
        _pending_stack->exp_rand_max = $6;
    }
    | S RANDOM_UINT LPAREN NUMBER COMMA NUMBER RPAREN SEMICOLON {
        _pending_stack->s_type = VAL_TYPE_RANDOM;
        _pending_stack->s_rand_min = $4;
        _pending_stack->s_rand_max = $6;
    }

%%

int parse_rules(const char *filename, rule_t **rules) {
    _filename = filename;
    _rules = NULL;
    _retval = 0;

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_fatal("failed to open config file %s", filename);
        return -1;
    }

    yyin = f;

    _pending_stack = (stack_t *) malloc(sizeof(stack_t));
    memset(_pending_stack, 0, sizeof(stack_t));

    _current_rule = NULL;
    _current_hops = NULL;
    _prev_stack = NULL;
    _current_hop_index = 1000; // magic value for "no hops defined"

    yyparse();
    
    fclose(f);

    free(_pending_stack);

    *rules = _rules;

    return _retval;
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    _retval = -1;
}

int new_rule() {
    _current_hop_index = 1000; // magic value for "no hops defined"

    rule_t *prev_rule = _current_rule;

    _current_rule = (rule_t *) malloc(sizeof(rule_t));
    memset(_current_rule, 0, sizeof(rule_t));
    
    if (_rules == NULL) {
        _rules = _current_rule;
    }

    if (prev_rule != NULL) {
        prev_rule->next = _current_rule;
    }

    return 0;
}

int new_hop() {
    _prev_stack = NULL;

    if (_current_hop_index == 1000) {
        _current_hops = calloc(255, sizeof(hop_t));
        _current_rule->hops = _current_hops;
        _current_hop_index = 0;
    } else {
        ++_current_hop_index;
    }

    _current_rule->nhops = _current_hop_index + 1;

    if (_current_hop_index > 255) {
        log_fatal("too many hops defined (255 max)");
        return -1;
    }

    return 0;
}

int save_stack() {
    stack_t *new_stack = (stack_t *) malloc(sizeof(stack_t));
    memcpy(new_stack, _pending_stack, sizeof(stack_t));
    memset(_pending_stack, 0, sizeof(stack_t));

    if (_prev_stack != NULL) {
        _prev_stack->next = new_stack;
        _prev_stack = new_stack;
    } else {
        _current_hop.stack = new_stack;
        _prev_stack = new_stack;
    }

    return 0;
}

int set_rule_from(uint32_t ip, uint32_t mask) {
    if (mask > 32) {
        log_error("invalid mask: '/%d'\n", mask);
        yyerror("invalid value for mask, aborting.");
        return -1;
    }

    _current_rule->from = ip;
    _current_rule->from_mask = CIDR_MASK_MAP[mask];

    return 0;
}

int set_rule_to(uint32_t ip, uint32_t mask) {
    if (mask > 32) {
        log_error("invalid mask: '/%d'\n", mask);
        yyerror("invalid value for mask, aborting.");
        return -1;
    }

    _current_rule->to = ip;
    _current_rule->to_mask = CIDR_MASK_MAP[mask];

    return 0;
}