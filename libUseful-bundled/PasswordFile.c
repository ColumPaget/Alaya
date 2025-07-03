#include "PasswordFile.h"
#include "Entropy.h"
#include "Hash.h"




void PasswordEntryDestroy(void *p_Entry)
{
TPasswordEntry *Entry;

if (! p_Entry) return;

Entry=(TPasswordEntry *) p_Entry;
Destroy(Entry->User);
Destroy(Entry->Type);
Destroy(Entry->Salt);
Destroy(Entry->Cred);
Destroy(Entry->Extra);

Destroy(Entry);
}


TPasswordEntry *PasswordFileParse(const char *Line)
{
const char *ptr;
TPasswordEntry *Entry;
char *Token=NULL;

Entry=(TPasswordEntry *) calloc(1, sizeof(TPasswordEntry));

ptr=GetToken(Line, ":", &(Entry->User), GETTOKEN_QUOTES);
//Entry->User=UnQuoteStr(Entry->User, Token);
ptr=GetToken(ptr, ":", &(Entry->Type), 0);
ptr=GetToken(ptr, ":", &(Entry->Salt), 0);
ptr=GetToken(ptr, ":", &(Entry->Cred), GETTOKEN_QUOTES);
ptr=GetToken(ptr, ":", &(Entry->Extra), GETTOKEN_QUOTES);

return(Entry);
}


char *PasswordFileGenerateEntry(char *RetStr, const char *User, const char *PassType, const char *Password, const char *Extra)
{
    char *Salt=NULL, *Hash=NULL, *Tempstr=NULL;

    if (StrEnd(PassType) || (strcasecmp(PassType, "plain")==0) )
    {
        Salt=CopyStr(Salt, "");
	//in plain text passwords it's not really a hash, just the plain password
	//and we have to quote it because ppl could include :'\"\r or \n in the password
        Hash=QuoteCharsInStr(Hash, Password, ":'\"\r\n");
    }
    else
    {
        Salt=GetRandomAlphabetStr(Salt, 20);
        Tempstr=MCatStr(Tempstr, Salt, Password, NULL);
	//a base64 encoded hash won't contain any problem characters, so we don't need to encode it
        HashBytes(&Hash, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
    }

    RetStr=QuoteCharsInStr(RetStr, User, ":'\"\r\n");
    Tempstr=QuoteCharsInStr(Tempstr, Extra, ":'\"\r\n");
    RetStr=MCatStr(RetStr, ":", PassType, ":", Salt, ":", Hash, ":", Tempstr, "\n", NULL);

    Destroy(Tempstr);
    Destroy(Hash);
    Destroy(Salt);

    return(RetStr);
}





int PasswordFileDelete(const char *Path, const char *User)
{
STREAM *Old, *New;
int RetVal=FALSE;
char *Tempstr=NULL, *Token=NULL;

    Old=STREAMOpen(Path, "rL");

    Tempstr=MCopyStr(Tempstr, Path, "+", NULL);
    New=STREAMOpen(Tempstr, "wL");

    if (New && Old)
    {
            Tempstr=STREAMReadLine(Tempstr, Old);
            while (Tempstr)
            {
                GetToken(Tempstr, ":", &Token, GETTOKEN_QUOTES);
                if (strcmp(User, Token) == 0) RetVal=TRUE;
		else STREAMWriteLine(Tempstr, New);
                Tempstr=STREAMReadLine(Tempstr, Old);
            }
            STREAMClose(Old);

        if (RetVal==TRUE)
	{
	  if (rename(New->Path, Path) != 0) 
	  {
		RetVal=FALSE;
		RaiseError(ERRFLAG_DEBUG, "PasswordFileDelete", "can't rename [%s] to [%s]", New->Path, Path);
	  }
	}
	else unlink(New->Path);

        STREAMClose(New);
    }
    else
    {
     if (Old) STREAMClose(Old);
     else RaiseError(ERRFLAG_DEBUG, "PasswordFileDelete", "failed to open: [%s]", Path);
     if (New) STREAMClose(New);
     else RaiseError(ERRFLAG_DEBUG, "PasswordFileDelete", "failed to open: [%s]", Tempstr);
    }

Destroy(Tempstr);
Destroy(Token);

return(RetVal);
}


int PasswordFileAppend(const char *Path, const char *PassType, const char *User, const char *Password, const char *Extra)
{
    STREAM *S;
    char *Tempstr=NULL, *Token=NULL;
    int RetVal=FALSE;

    S=STREAMOpen(Path, "aL");
    if (! S) return(FALSE);

    STREAMSeek(S, 0, SEEK_END);
    Tempstr=PasswordFileGenerateEntry(Tempstr, User, PassType, Password, Extra);
    STREAMWriteLine(Tempstr, S);
    STREAMClose(S);

    Destroy(Tempstr);
    Destroy(Token);

    return(RetVal);
}


int PasswordFileAdd(const char *Path, const char *PassType, const char *User, const char *Password, const char *Extra)
{
int RetVal;

    PasswordFileDelete(Path, User);
    RetVal=PasswordFileAppend(Path, PassType, User, Password, Extra);

    return(RetVal);
}



TPasswordEntry *PasswordFileReadEntry(STREAM *S)
{
char *Tempstr=NULL;
TPasswordEntry *Entry=NULL;

        Tempstr=STREAMReadLine(Tempstr, S);
        if (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
	    Entry=PasswordFileParse(Tempstr);
        }

Destroy(Tempstr);

return(Entry);
}



TPasswordEntry *PasswordFileGet(const char *Path, const char *User)
{
    TPasswordEntry *Entry=NULL;
    STREAM *S;

    if (! StrValid(Path)) return(NULL);
    if (! StrValid(User)) return(NULL);

    S=STREAMOpen(Path, "rl");
    if (S)
    {
	Entry=PasswordFileReadEntry(S);
        while (Entry)
        {
	    if (strcmp(Entry->User, User) == 0) break;

	    //if it matches we won't get here
	    PasswordEntryDestroy(Entry);
            Entry=NULL;  	
	    Entry=PasswordFileReadEntry(S);
        }

        STREAMClose(S);
    }
    else RaiseError(ERRFLAG_DEBUG, "PasswordFileGet", "can't open %s", Path);

    return(Entry);
}


static int PasswordFileMatchItem(const char *Data, const char *User, const char *Password)
{
    char *Tempstr=NULL, *ProvidedCred=NULL;
    const char *ptr;
    TPasswordEntry *Entry=NULL;
    int result=FALSE;

    Entry=PasswordFileParse(Data);
    if (! Entry) return(FALSE);

    if (strcmp(Entry->User, User)==0)
    {
	//for 'plain' password type we're going to compare against the  raw password
        if ( (! StrValid(Entry->Type)) || (strcmp(Entry->Type, "plain")==0) ) ProvidedCred=CopyStr(ProvidedCred, Password);
        else
        {
	    //for other password types, we salt the password with the salt from the creds file,
	    //then when we hash it we should get the same password as stored in the creds file
            Tempstr=MCopyStr(Tempstr, Entry->Salt, Password, NULL);
            HashBytes(&ProvidedCred, Entry->Type, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
        }

        if (strcmp(ProvidedCred, Entry->Cred) == 0) result=TRUE;
    }

    PasswordEntryDestroy(Entry);

    Destroy(Tempstr);
    Destroy(ProvidedCred);

    return(result);
}


int PasswordFileCheck(const char *Path, const char *User, const char *Password, char **Extra)
{
    STREAM *F;
    char *Tempstr=NULL;
    const char *ptr;
    int result=FALSE;

    if (! StrValid(Path)) return(FALSE);
    if (! StrValid(User)) return(FALSE);

    F=STREAMOpen(Path, "rl");
    if (F)
    {
        Tempstr=STREAMReadLine(Tempstr, F);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            result=PasswordFileMatchItem(Tempstr, User, Password);
            if (result)
            {
                if (Extra)
                {
                    ptr=strrchr(Tempstr, ':');
                    *Extra=UnQuoteStr(*Extra, ptr+1);
                }
                break;
            }

            Tempstr=STREAMReadLine(Tempstr, F);
        }

        STREAMClose(F);
    }
    else RaiseError(ERRFLAG_DEBUG, "PasswordFileCheck", "can't open %s", Path);
    Destroy(Tempstr);

    return(result);
}
