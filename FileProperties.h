#ifndef ALAYA_PAGE_EDIT
#define ALAYA_PAGE_EDIT

#include "common.h"

#define FILE_PROPERTY 1
#define FILE_USER_VALUE 2

void SetProperties(const char *File, ListNode *Props);
int LoadFileRealProperties(const char *FName, int ExamineContents, ListNode *Vars);
int LoadFileProperties(const char *Path, ListNode *PropList);
int PropertiesLoadFromStream(const char *FName, STREAM *S, ListNode *Vars);


#endif



