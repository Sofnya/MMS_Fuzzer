#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "string_utilities.h"
#include "iec61850_common.h"
#include "mms_client_connection.h"
#include "conversions.h"

static void
print_help()
{
    printf("TestClient options:\n");
    printf("-h <hostname> specify hostname\n");
    printf("-p <port> specify port\n");
    printf("-m print raw MMS messages\n");
}

void printRawMmsMessage(void *parameter, uint8_t *message, int messageLength, bool received)
{
    if (received)
        printf("RECV: ");
    else
        printf("SEND: ");

    int i;
    for (i = 0; i < messageLength; i++)
    {
        printf("%02x ", message[i]);
    }

    printf("\n");
}

void test(MmsConnection con)
{
    MmsError error;
    MmsError *err = &error;
    LinkedList res, vars;
    MmsValue *testValue = MmsValue_newInteger(1);
    MmsValue *testArray = MmsValue_createEmptyArray(2);
    MmsValue_setElement(testArray, 0, MmsValue_newInteger(1));
    MmsValue_setElement(testArray, 1, MmsValue_newInteger(2));

    LinkedList testVarNames = LinkedList_create();
    LinkedList_add(testVarNames, "name1");
    LinkedList_add(testVarNames, "ba2");
    LinkedList testVarValues = LinkedList_create();
    LinkedList_add(testVarValues, MmsValue_newInteger(3));
    LinkedList_add(testVarValues, MmsValue_newInteger(4));

    LinkedList testAccessSpecs = LinkedList_create();
    LinkedList_add(testAccessSpecs, MmsVariableAccessSpecification_create("testDomain", "name1"));
    LinkedList_add(testAccessSpecs, MmsVariableAccessSpecification_create("testDomain", "ba2"));

    char *dom, *tmp, *jour;
    int a, b, c;
    long d;

    MmsConnection_getVMDVariableNames(con, err);
    puts("Got VMD variable names");
    res = MmsConnection_getDomainNames(con, err);
    if (*err != MMS_ERROR_NONE)
    {
        puts("Error getting domain names");
        printf("Error code: %i", *err);
    }
    else
    {
        puts("Got domain names");
    }
    res = LinkedList_getNext(res);
    dom = (char *)LinkedList_getData(res);
    printf("Got domain name:%s\n", dom);
    vars = MmsConnection_getDomainVariableNames(con, err, dom);
    vars = LinkedList_getNext(vars);
    vars = LinkedList_getNext(vars);
    tmp = (char *)LinkedList_getData(vars);
    printf("Got variable name:%s\n", tmp);
    MmsConnection_getDomainVariableListNames(con, err, dom);
    puts("Got domain variable list names");
    res = MmsConnection_getDomainJournals(con, err, dom);
    jour = (char *)LinkedList_getData(res);
    printf("Got domain journals:%s\n", jour);
    MmsConnection_getVariableListNamesAssociationSpecific(con, err);
    puts("Got variable list names");
    MmsConnection_readVariable(con, err, dom, tmp);
    puts("Read variable");
    MmsConnection_readVariableComponent(con, err, dom, tmp, "a");
    puts("Read variable component");
    MmsConnection_readArrayElements(con, err, dom, tmp, 0, 5);
    puts("Read array elements");
    MmsConnection_readSingleArrayElementWithComponent(con, err, dom, tmp, 0, "a");
    puts("Read single array element with component");
    MmsConnection_readMultipleVariables(con, err, dom, testVarNames);
    puts("Read multiple variables");
    MmsConnection_writeVariable(con, err, dom, tmp, testValue);
    puts("Write variable");
    MmsConnection_writeSingleArrayElementWithComponent(con, err, dom, tmp, 1, "a", testValue);
    puts("Write single array element with component");
    MmsConnection_writeArrayElements(con, err, dom, tmp, 0, 2, testArray);
    puts("Write array elements");
    MmsConnection_writeMultipleVariables(con, err, dom, testVarNames, testVarValues, NULL);
    puts("Write multiple variables");
    MmsConnection_getVariableAccessAttributes(con, err, dom, tmp);
    puts("Get variable access attributes");
    MmsConnection_readNamedVariableListValues(con, err, dom, tmp, true);
    puts("Read named variable list values");
    MmsConnection_readNamedVariableListValuesAssociationSpecific(con, err, tmp, false);
    puts("Read named variable list values association specific");
    MmsConnection_defineNamedVariableList(con, err, dom, "aaaa", testAccessSpecs);
    puts("Define named variable list");
    MmsConnection_defineNamedVariableListAssociationSpecific(con, err, "bbbbb", testAccessSpecs);
    puts("Define named variable list association specific");
    MmsConnection_writeNamedVariableList(con, err, true, dom, "aaaa", testVarValues, NULL);
    puts("Write named variable list");
    MmsConnection_readNamedVariableListDirectory(con, err, dom, "aaaa", NULL);
    puts("Read named variable list directory");
    MmsConnection_readNamedVariableListDirectoryAssociationSpecific(con, err, "aaaa", NULL);
    puts("Read named variable list directory association specific");
    MmsConnection_deleteNamedVariableList(con, err, dom, "aaaa");
    puts("Delete named variable list");
    MmsConnection_deleteAssociationSpecificNamedVariableList(con, err, "aaaa");
    puts("Delete association specific named variable list");
    MmsConnection_identify(con, err);
    puts("Identify");
    MmsConnection_getServerStatus(con, err, &a, &b, true);
    puts("Get server status");
    MmsConnection_getFileDirectory(con, err, NULL, NULL, NULL, NULL);
    puts("Get file directory");
    c = MmsConnection_fileOpen(con, err, "fileName", 0, &a, &d);
    puts("File open");
    MmsConnection_fileRead(con, err, c, NULL, NULL);
    puts("File read");
    MmsConnection_fileClose(con, err, c);
    puts("File close");
    MmsConnection_fileRename(con, err, "fileName", "newName");
    puts("File rename");
    MmsConnection_obtainFile(con, err, "newName", "newName");
    puts("Obtain file");
    MmsConnection_fileDelete(con, err, "newName");
    puts("File delete");
    MmsConnection_readJournalTimeRange(con, err, dom, "journ", MmsValue_newBinaryTime(true), MmsValue_newBinaryTime(false), (bool *)&c);
    puts("Read journal time range");
    MmsConnection_readJournalStartAfter(con, err, dom, "journ", MmsValue_newBinaryTime(true), MmsValue_newOctetString(0, 4), (bool *)&c);
    puts("Read journal start after");
    MmsConnection_conclude(con, err);
    puts("Conclude");
    // MmsConnection_abort(con, &err);
}

int main(int argc, char **argv)
{
    int returnCode = 0;

    char *hostname = StringUtils_copyString("localhost");
    int tcpPort = 102;
    int maxPduSize = 65000;
    int arrayIndex = -1;
    int printRawMmsMessages = 0;

    int c;

    while ((c = getopt(argc, argv, "mh:p:")) != -1)
    {
        switch (c)
        {
        case 'm':
            printRawMmsMessages = 1;
            break;

        case 'h':
            free(hostname);
            hostname = StringUtils_copyString(optarg);
            break;
        case 'p':
            tcpPort = atoi(optarg);
            break;
        default:
            print_help();
            return 0;
        }
    }

    MmsConnection con = MmsConnection_create();

    MmsError error;

    /* Set maximum MMS PDU size (local detail) */
    MmsConnection_setLocalDetail(con, maxPduSize);

    if (printRawMmsMessages)
        MmsConnection_setRawMessageHandler(con, (MmsRawMessageHandler)printRawMmsMessage, NULL);

    if (!MmsConnection_connect(con, &error, hostname, tcpPort))
    {
        printf("MMS connect failed!\n");

        if (error != MMS_ERROR_NONE)
            returnCode = error;
    }
    else
    {
        printf("MMS connected.\n");
        test(con);
    }
    MmsConnection_destroy(con);

    return returnCode;
}
