#include "domain_conf.h"
#include "ch_conf.h"

int
chInterfaceEthernetConnect(virDomainDef *def,
                           virCHDriver *driver,
                           virDomainNetDef *net,
                           int *tapfd,
                           size_t tapfdSize);

int chInterfaceBridgeConnect(virDomainDef *def,
                           virCHDriver *driver,
                           virDomainNetDef *net,
                           int *tapfd);

int chInterfaceStartDevices(virDomainDef *def);
