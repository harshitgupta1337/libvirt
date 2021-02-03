#include "domain_conf.h"
#include "ch_conf.h"

int chInterfaceBridgeConnect(virDomainDefPtr def,
                           virCHDriverPtr driver,
                           virDomainNetDefPtr net,
                           int *tapfd,
                           size_t *tapfdSize);