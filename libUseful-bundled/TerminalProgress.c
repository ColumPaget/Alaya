#include "TerminalProgress.h"

TERMPROGRESS *TerminalProgressCreate(STREAM *Term, const char *Config)
{
    TERMPROGRESS *TP;

    TP=TerminalWidgetCreate(Term, "type=progress");
    TerminalWidgetParseConfig(TP, Config);
    return(TP);
}


//this builds the 'text' of the progress bar, but does not add
//colors. The text can come from two sources. The 'innertext'
//variable is intended for text displayed 'above' the progress bar
//with the progress bar being supplied by colors changing 'under' it.
//The 'progress' and 'remain' variables supply characters to be used as
//the 'bar' and 'remainder' parts of the progress bar.
//These two systems are at odds with each other, so best to use one
//or the other.
static char *TerminalProgressBuildInnerText(char *Bar, TERMPROGRESS *TP, float Fract, int used, int wide)
{
    int blen, len, pos;
    char *Tempstr=NULL;
    ListNode *Vars;
    const char *ptr;

    //use the "progress" variable to specify the character used to
    //pad out the 'used' part of the progress bar. If no character
    //is specified, then use space.
    len=(int) used;
    ptr=GetVar(TP->Options, "progress");
    if (! StrValid(ptr)) ptr=" ";
    Tempstr=PadStr(Tempstr, *ptr, len);

    //Bar=CatStr(Bar, Tempstr);
    //use the "remain" variable to specify the character used to
    //pad out the 'unused' part of the progress bar. If no character
    //is specified, then use space.

    ptr=GetVar(TP->Options, "remain");
    if (! StrValid(ptr)) ptr=" ";
    Tempstr=PadStr(Tempstr, *ptr, wide - len);

    Bar=CatStr(Bar, Tempstr);

    //now, if 'innertext' is supplied, splat that over the bar
    //we have created

    ptr=GetVar(TP->Options, "innertext");
    if (StrValid(ptr))
    {
        Vars=ListCreate();
        SetNumericVar(Vars, "percent",(int) (100 * Fract));
        Tempstr=SubstituteVarsInString(Tempstr, ptr, Vars, 0);
        ListDestroy(Vars, Destroy);

        blen=StrLen(Bar);
        len=StrLen(Tempstr);
        if (len >= blen)
        {
            len=blen;
            pos=0;
        }
        else
        {
            pos=blen / 2 - len / 2;
        }

        strncpy(Bar+pos, Tempstr, len);
    }

    Destroy(Tempstr);

    return(Bar);
}


void TerminalProgressDraw(TERMPROGRESS *TP, float Fract, const char *Info)
{
    char *Tempstr=NULL, *Bar=NULL, *Remain=NULL;
    const char *ptr;
    int len, wide, used;

    wide=TP->wid;
    used=(int) (wide * Fract + 0.5);

    if (TP->Term)
    {
        if (wide < 0) wide=atoi(STREAMGetValue(TP->Term, "Terminal:cols")) + TP->wid - TP->x - TerminalStrLen(TP->Text) - TerminalStrLen(Info);
    }

    if (TP->Flags & TERMMENU_POSITIONED) TerminalCommand(TERM_CURSOR_MOVE, TP->x, TP->y, TP->Term);
    else Tempstr=CopyStr(Tempstr, "\r");

    //if there's a 'prompt' or title to the bar, then add that
    if (StrValid(TP->Text)) Tempstr=CatStr(Tempstr, TP->Text);

    //now we add  any 'left' container text to the bar and
    //the escape-sequences for the initial color of the bar.
    //'SelectedAttribs' here is the color values for the
    //'used' part of the progress bar
    Tempstr=MCatStr(Tempstr, TP->CursorLeft, TP->SelectedAttribs, NULL);

    //now we add text for the used part of the bar
    Bar=TerminalProgressBuildInnerText(Bar, TP, Fract, used, wide);
    Tempstr=CatStrLen(Tempstr, Bar, used);

    //now we add color attributes for the unused part of the bar
    if (StrValid(TP->Attribs)) Tempstr=CatStr(Tempstr, TP->Attribs);
    else if (StrValid(TP->SelectedAttribs)) Tempstr=CatStr(Tempstr, "~0");


    //now we add text for the unused part of the bar
    Tempstr=CatStr(Tempstr, Bar+used);

    //now we end the bar and add any 'container' text on the right side
    if (StrValid(TP->Attribs)) Tempstr=CatStr(Tempstr, "~0");
    Tempstr=CatStr(Tempstr, TP->CursorRight);

    if (StrValid(Info)) Tempstr=MCatStr(Tempstr, Info, "~>", NULL);

    TerminalPutStr(Tempstr, TP->Term);
    STREAMFlush(TP->Term);

    Destroy(Tempstr);
    Destroy(Remain);
    Destroy(Bar);
}




float TerminalProgressUpdate(TERMPROGRESS *TP, int Value, int Max, const char *Info)
{
    float Fract;

    Fract=((float) Value) / ((float) Max);

    TerminalProgressDraw(TP, Fract, Info);
    return(Fract);
}


