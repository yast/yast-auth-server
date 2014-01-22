/* Y2CCSlapdConfigAgent.cc
 *
 * Slapd back-config agent implementation
 *
 * Authors: Ralf Haferkamp <rhafer@suse.de>
 *
 * $Id$
 */

#include <scr/Y2AgentComponent.h>
#include <scr/Y2CCAgentComponent.h>

#include "SlapdConfigAgent.h"

typedef Y2AgentComp <SlapdConfigAgent> Y2SlapdConfigAgentComp;

Y2CCAgentComp <Y2SlapdConfigAgentComp> g_y2ccag_slapdconfig ("ag_slapdconfig");
