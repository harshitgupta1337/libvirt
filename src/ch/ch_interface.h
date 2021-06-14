#include "domain_conf.h"
#include "ch_conf.h"

int chInterfaceBridgeConnect(virDomainDef *def,
                           virCHDriver *driver,
                           virDomainNetDef *net,
                           int *tapfd,
                           size_t *tapfdSize);