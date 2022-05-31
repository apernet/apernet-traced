#ifndef APERNET_TRACED_CONFIG_H
#define APERNET_TRACED_CONFIG_H
#include "trace.h"

/**
 * @brief parse rules from config file.
 * 
 * @param filename file name of config file.
 * @param rules pointer to pointer of rules to store parsed rules. free with
 * destroy_rules().
 * @return int 0 on success, -1 on error.
 */
int parse_rules(const char *filename, rule_t **rules);

/**
 * @brief destroy (free) rules struct.
 * 
 * @param rules pointer to rules.
 */
void destroy_rules(rule_t *rules);

#endif // APERNET_TRACED_CONFIG_H