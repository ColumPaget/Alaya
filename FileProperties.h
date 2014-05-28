#ifndef ALAYA_PAGE_EDIT
#define ALAYA_PAGE_EDIT

#include "common.h"

#define FILE_PROPERTY 1
#define FILE_USER_VALUE 2

void SetProperties(char *File, ListNode *Props);
int LoadFileProperties(char *Path, ListNode *PropList);

#endif



