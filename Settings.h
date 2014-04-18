#include "common.h"

#ifndef ALAYA_COMMANDLINE_H
#define ALAYA_COMMANDLINE_H

void ParseConfigItem(char *ConfigLine);
void ParseConfigItemList(const char *Settings);
void ParseSettings(int argc, char *argv[], TSettings *Settings);

#endif

