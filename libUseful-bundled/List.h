/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

#ifndef LIBUSEFUL_LIST
#define LIBUSEFUL_LIST

/*

This module provides double linked lists and 'maps'. Maps are hashed arrays of linked lists, so they're very good for storing large numbers of items that can be looked up by a key or name. 

Items are stored as (void *) pointers, and can be tagged with a name by using 'ListAddNamedItem'. 

When the list is destroyed by the 'ListDestroy' function, a Destructor function can be passed in as the second argument which is used to destroy items stored in the list. If the items in the list aren't unique copies, but are pointers to things that exist outside of the list, then pass NULL as the destructor.

For example, the following adds two un-named items to a list (the strings "item 1" and "item 2" are the data stored in the list, not name tags for items):


```
ListNode *MyList, *Curr;

MyList=ListCreate();
ListAdd(MyList, CopyStr(NULL, "item 1"));
ListAdd(MyList, CopyStr(NULL, "item 2"));

Curr=ListGetNext(MyList);
while (Curr)
{
printf("%s\n", (const char *) Curr->Item);
Curr=ListGetNext(Curr);
}

ListDestroy(MyList, Destroy);
```


Here we add two strings to the list, and use 'CopyStr' to make unique copies of them. These are then destroyed/freed using the standard 'Destroy' function, which is passed in as the second argument of 'ListDestroy'.


Maps work similarly, with the only difference being the use of 'MapCreate' with a 'number of chains' argument. The below code creates a map of named items, with 128 sub-lists ("chains") in the map. It then looks up each of the items added and prints out their name tag.


```
ListNode *MyList, *Curr;
char *Tempstr=NULL;
int i;

MyList=MapCreate(128, 0);

for (i=0; i < 10000; i++)
{
Tempstr=FormatStr(Tempstr, "item %d", i);
ListAddNamedItem(MyList, Tempstr, CopyStr(NULL, Tempstr));
}


for (i=0; i < 10000; i++)
{
Tempstr=FormatStr(Tempstr, "item %d", i);
Curr=ListFindNamedItem(MyList, Tempstr);
if (Curr) printf("Found: %s\n", Curr->Tag);
}


ListDestroy(MyList, Destroy);
```


Various flags can be passed as an optional Argument to 'ListCreate', e.g.


```

MyList=ListCreate(LIST_FLAG_CACHE);

```

or as the second argument of 'MapCreate', e.g.

```

MyList=MapCreate(4096, LIST_FLAG_CACHE);

```


The 'LIST_FLAG_CACHE' flag used in these examples caches the last item found in a lookup, so that if the same item is looked up many times in a row,
it is returned more quickly. This is particularly useful with large maps with many sub-lists and many items in each sub-list, as the likelyhood of 
looking up the same item twice in a given chain is much higher, as that chain is only visited for a subset of items in the map. This can speed up
lookups as the whole sub-chain does not have to be explored to find the item, as the cached item will be returned immediately.


The maximum length of a list, or of each subchain in a map, can be set with 'ListSetMaxItems', and Items can be timed-out from the
list using 'LIST_FLAG_TIMEOUT. 

*/







// Functions passsed to 'ListCreate' or 'MapCreate' or set against a ListNode item
#define LIST_FLAG_DELETE      1   //internally used flag, currently unused
#define LIST_FLAG_CASE        2   //when doing searches with 'ListFindNamedItem' etc, use case
#define LIST_FLAG_SELFORG     4   //self organize list so most used items are at the top
#define LIST_FLAG_ORDERED     8   //create an 'ordered' list (so insert items in order)
#define LIST_FLAG_CACHE      16   //cache the last found item (especially useful for maps)
#define LIST_FLAG_TIMEOUT    32   //remove items in the list that are older than the time set against them using 'ListNodeSetTime'
#define LIST_FLAG_MAP_HEAD   64   //internally used flag to specify this node is the head of a map
#define LIST_FLAG_MAP_CHAIN 128   //internally used flag to specify this node is the head of a map chain
#define LIST_FLAG_MAP (LIST_FLAG_MAP_HEAD | LIST_FLAG_MAP_CHAIN) //internally used flag 
#define LIST_FLAG_STATS     256   //internally used flag

//list contains only one instance of a named item, so don't keep searching after first find.
//N.B. This ignores item type, one instance of a name means exactly that, NOT one instance of 
//name and type. It's specifically for use in cases where items are uniquely named but might
//have different types, or the type value might be being used for some other purpose. It
//allows list to return 'not found' as soon as it can
#define LIST_FLAG_UNIQ  512     
                             


//these flags are available to be set against a listnode for whatever purpose the user
//desires
#define LIST_FLAG_USER1   1024
#define LIST_FLAG_USER2   2048
#define LIST_FLAG_USER3   4096
#define LIST_FLAG_USER4   8192
#define LIST_FLAG_USER5  16384


#define LIST_FLAG_DEBUG  32768


#define LIST_ITEM_ANYTYPE -1


#include <time.h>



#ifdef __cplusplus
extern "C" {
#endif

// function prototypes for 'destroy' and 'clone' functions used by
// 'DestroyList' and 'CloneList'
typedef void (*LIST_ITEM_DESTROY_FUNC)(void *);
typedef void *(*LIST_ITEM_CLONE_FUNC)(void *);



//ListStats started out as a structure to store how many times a node in a list is accessed ("Hits")
//and it's last access time. However, since then it's become a multi-use structure. 

//Data nodes in a list only have a "ListStats" item if the list has been created with the LIST_FLAG_STATS flag
//or if they've been created with the LIST_FLAG_TIMEOUT (see below)

//Head nodes of a list don't have a "Hits" value, and instead "Hits" is used to store the number
//of items in the list. For this and other reasons, head nodes always have a 'stats' subitem.

//If LIST_FLAG_TIMEOUT is set on a list, then the 'Time' field is used in combination 
//with the 'ListNodeSetTime' function to set an expiry time for items in a list. In this
//situation 'last access time' is not available. 

//If the 'ListSetMaxItems' function is used to set a maximum number of items in the list, then the 'Max'
//value is set in ListStats, and if the list, or a chain in a map, has more items than this, then
//items are deleted from the top of the list. Items at the top are presumed to be the oldest, but this
//may not be true with self-ordered lists.

//Destroyer is a function that can be set with either 'ListSetDestroyer' or 'ListSetMaxItems' which is
//called to destroy items in the list when they time out, or are deleted because the list has exceeded
//the 'Max' items level.
 

typedef struct
{
    time_t Time;
//In the 'head' item 'Hits' is used to hold the count of items in the list
    unsigned long Hits;
    unsigned long Max;
		LIST_ITEM_DESTROY_FUNC Destroyer;
} ListStats;


//attempt to order items in likely use order, this *might* help the L1 cache
//is 32 bytes, so should fit in one cache line
typedef struct lnode
{
    struct lnode *Next;
    struct lnode *Prev;
    char *Tag;
//in map heads ItemType is used to hold the number of buckets
//in bucket chain heads, it holds the chain number
    uint16_t ItemType;
    uint16_t Flags;
    struct lnode *Head;
    void *Item;
    struct lnode *Side;
    ListStats *Stats;
} ListNode;


//below are macros for things not worthy of a full function or which pull tricks with macros

//this allows 'ListCreate' to be called with flags or without
#define ListCreate(F) (ListInit(F + 0))


//Get first item in a list, or in a map chain
#define MapChainGetHead(Node) (((Node)->Flags & LIST_FLAG_MAP_CHAIN) ? (Node) : Node->Head)

//if L isn't NULL then return L->Head, it's fine if L->Head is null
#define ListGetHead(Node) ((Node) ? MapChainGetHead(Node) : NULL)

#define ListNodeGetHits(node) ((node)->Stats ? (node)->Stats->Hits : 0)
#define ListNodeGetTime(node) ((node)->Stats ? (node)->Stats->Time : 0)


//#define ListGetNext(Node) (Node ? (((Node)->Head->Flags & (LIST_FLAG_MAP|LIST_FLAG_MAP_CHAIN)) ? MapGetNext(Node) : (Node)->Next) : NULL)
#define ListGetNext(Node) ((Node) ? MapGetNext(Node) : NULL)

//listDeleteNode handles ListFindItem returning NULL, so no problems here
#define ListDeleteItem(list, item) (ListDeleteNode(ListFindItem((list), (item))))

#define ListInsertItem(list, item) (ListInsertTypedItem((list), 0, "", (item)))
#define ListAddItem(list, item) (ListAddTypedItem((list), 0, "", (item)))

#define ListInsertNamedItem(list, name, item) (ListInsertTypedItem((list), 0, (name), (item)))
#define ListAddNamedItem(list, name, item) (ListAddTypedItem((list), 0, (name), (item)))


//Again, NULL is handled here by ListInsertTypedItem
#define OrderedListAddNamedItem(list, name, item) (ListInsertTypedItem(ListFindNamedItemInsert((list), (name)), 0, (name), (item)))

//in map heads ItemType is used to hold the number of buckets
#define MapChainCount(Head) (((Head)->Flags & LIST_FLAG_MAP) ? (Head)->ItemType : 0)



//real functions start here

unsigned long ListSize(ListNode *Node);

//Dump stats on hash distribution in a map
void MapDumpSizes(ListNode *Head);

//create a list
ListNode *ListInit(int Flags);

//SetFlags on a list
void ListSetFlags(ListNode *List, int Flags);


//Set a function that will be called to destroy items in the list
//this is used by The List-Max-Items and LIST_FLAT_TIMEOUT features
void ListSetDestroyer(ListNode *List, LIST_ITEM_DESTROY_FUNC Destroyer);

//Set maximum length of the list. For maps, this will be
//the maximum length that any chain can grow to.
void ListSetMaxItems(ListNode *Node, unsigned long Max, LIST_ITEM_DESTROY_FUNC Destroyer);


//Set time on a list. Normally this is automatically set on insertion
void ListNodeSetTime(ListNode *Node, time_t When);

//set number of hits on a listnode, This is normally set by 'ListFindNamedItem' 
void ListNodeSetHits(ListNode *Node, int Hits);

//add to number of hits on a listnode
int ListNodeAddHits(ListNode *Node, int Hits);


//create a map
ListNode *MapCreate(int Buckets, int Flags);

//get nth chain in a maps hashmap
ListNode *MapGetNthChain(ListNode *Map, int n);

//get the map chain that hashes to 'Key'
ListNode *MapGetChain(ListNode *Map, const char *Key);

//destroy a list or a map
void ListDestroy(ListNode *, LIST_ITEM_DESTROY_FUNC);

//clear all items from a list or a map
void ListClear(ListNode *, LIST_ITEM_DESTROY_FUNC);


//slot a node into a list
void ListThreadNode(ListNode *Prev, ListNode *Node);

//unclip a node from a list
void ListUnThreadNode(ListNode *Node);

//add an item to a list or map, 'Type' is just a number used to identify different 
//types of thing in a list or map
ListNode *ListAddTypedItem(ListNode *List, uint16_t Type, const char *Name, void *Item);

//insert an item into a list at 'InsertPoint'
ListNode *ListInsertTypedItem(ListNode *InsertPoint,uint16_t Type, const char *Name,void *Item);



//get previous item in a list
ListNode *ListGetPrev(ListNode *);

//get last item in a list
ListNode *ListGetLast(ListNode *);

//get nth item in a list
ListNode *ListGetNth(ListNode *Head, int n);


ListNode *MapChainGetNext(ListNode *);

//get next item in a map
ListNode *MapGetNext(ListNode *);


//find node after which to insert an item in an ordered list
ListNode *ListFindNamedItemInsert(ListNode *Head, const char *Name);

//find an item of a given type by name
ListNode *ListFindTypedItem(ListNode *Head, int Type, const char *Name);

//find any item that name
ListNode *ListFindNamedItem(ListNode *Head, const char *Name);

//find a specific item
ListNode *ListFindItem(ListNode *Head, void *Item);

//Join lists together
ListNode *ListJoin(ListNode *List1, ListNode *List2);

//Clone a list. Function 'ItemCloner' creates a copy of the items (which could be any kind of structure or whatever)
ListNode *ListClone(ListNode *List, LIST_ITEM_CLONE_FUNC ItemCloner);

//Append a list of items to a list. This is different from 'join list' because instead of
//splicing two lists together, the ItemCloner function is used to create copies of the
//items and insert them into the destination list as new nodes
void ListAppendItems(ListNode *Dest, ListNode *Src, LIST_ITEM_CLONE_FUNC ItemCloner);

//sort a list of named items
void ListSortNamedItems(ListNode *List);

//sort a list of non-named items, using 'LessThanFunc' to compare them
void ListSort(ListNode *, void *Data, int (*LessThanFunc)(void *, void *, void *));

//Delete a node from a list. This returns the item that the node points to
void *ListDeleteNode(ListNode *);

//swap to items/listnodes in a list
void ListSwapItems(ListNode *Item1, ListNode *Item2);


#ifdef __cplusplus
}
#endif


#endif
