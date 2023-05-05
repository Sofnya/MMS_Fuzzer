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
    printf("-c <coverage> specify base coverage level\n");
    printf("-j <journal> specify journal coverage level\n");
    printf("-a <array> specify array coverage level\n");
    printf("-f <file> specify file coverage level\n");
    printf("-i <io> specify io coverage level\n");
    printf("-d <advanced> specify advanced coverage level\n");
    printf("-q <query> specify query coverage level\n");
    printf("-e <1|2|3|4> specify coverage preset\n");
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

void test(MmsConnection con, int testJournalsLevel, int testArraysLevel, int testFilesLevel, int testIOLevel, int testAdvancedLevel, int testQueryLevel)
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

    char *dom = "testDom", *tmp = "testVar", *jour = "testJournal";
    int a, b, c;
    long d;

    if (testQueryLevel > 0)
    {
        MmsConnection_getVMDVariableNames(con, err);
        puts("Got VMD variable names");

        res = MmsConnection_getDomainNames(con, err);
        if (*err != MMS_ERROR_NONE)
        {
            puts("Error getting domain names");
            printf("Error code: %i", *err);
        }
        res = LinkedList_getNext(res);
        dom = (char *)LinkedList_getData(res);
        printf("Got domain name:%s\n", dom);

        MmsConnection_identify(con, err);
        puts("Identify");

        MmsConnection_getServerStatus(con, err, &a, &b, true);
        puts("Get server status");
    }
    if (testQueryLevel > 1)
    {
        vars = MmsConnection_getDomainVariableNames(con, err, dom);
        vars = LinkedList_getNext(vars);
        vars = LinkedList_getNext(vars);
        tmp = (char *)LinkedList_getData(vars);
        printf("Got variable name:%s\n", tmp);
    }
    if (testQueryLevel > 2)
    {
        MmsConnection_getDomainVariableListNames(con, err, dom);
        puts("Got domain variable list names");
    }
    if (testQueryLevel > 3)
    {
        MmsConnection_getVariableListNamesAssociationSpecific(con, err);
        puts("Got domain variable list names association specific");
    }

    if (testIOLevel > 0)
    {
        MmsConnection_readVariable(con, err, dom, tmp);
        puts("Read variable");

        MmsConnection_writeVariable(con, err, dom, tmp, testValue);
        puts("Write variable");
    }
    if (testIOLevel > 1)
    {
        MmsConnection_readVariableComponent(con, err, dom, tmp, "a");
        puts("Read variable component");

        MmsConnection_readMultipleVariables(con, err, dom, testVarNames);
        puts("Read multiple variables");

        MmsConnection_readNamedVariableListValues(con, err, dom, tmp, true);
        puts("Read named variable list values");
    }
    if (testIOLevel > 2)
    {
        MmsConnection_readNamedVariableListDirectory(con, err, dom, "aaaa", NULL);
        puts("Read named variable list directory");

        MmsConnection_writeMultipleVariables(con, err, dom, testVarNames, testVarValues, NULL);
        puts("Write multiple variables");

        MmsConnection_writeNamedVariableList(con, err, true, dom, "aaaa", testVarValues, NULL);
        puts("Write named variable list");
    }
    if (testIOLevel > 3)
    {
        MmsConnection_readNamedVariableListDirectoryAssociationSpecific(con, err, "aaaa", NULL);
        puts("Read named variable list directory association specific");

        MmsConnection_readNamedVariableListValuesAssociationSpecific(con, err, tmp, false);
        puts("Read named variable list values association specific");
    }

    if (testArraysLevel > 0)
    {
        MmsConnection_readArrayElements(con, err, dom, tmp, 0, 5);
        puts("Read array elements");

        MmsConnection_writeArrayElements(con, err, dom, tmp, 0, 2, testArray);
        puts("Write array elements");
    }
    if (testArraysLevel > 1)
    {
        MmsConnection_readSingleArrayElementWithComponent(con, err, dom, tmp, 0, "a");
        puts("Read single array element with component");

        MmsConnection_writeSingleArrayElementWithComponent(con, err, dom, tmp, 1, "a", testValue);
        puts("Write single array element with component");
    }

    if (testAdvancedLevel > 0)
    {
        MmsConnection_getVariableAccessAttributes(con, err, dom, tmp);
        puts("Get variable access attributes");

        MmsConnection_deleteNamedVariableList(con, err, dom, "aaaa");
        puts("Delete named variable list");
    }
    if (testAdvancedLevel > 1)
    {
        MmsConnection_defineNamedVariableList(con, err, dom, "aaaa", testAccessSpecs);
        puts("Define named variable list");
    }
    if (testAdvancedLevel > 2)
    {
        MmsConnection_deleteAssociationSpecificNamedVariableList(con, err, "aaaa");
        puts("Delete association specific named variable list");

        MmsConnection_defineNamedVariableListAssociationSpecific(con, err, "bbbbb", testAccessSpecs);
        puts("Define named variable list association specific");
    }

    if (testFilesLevel > 0)
    {
        c = MmsConnection_fileOpen(con, err, "fileName", 0, &a, &d);
        puts("File open");

        MmsConnection_fileRead(con, err, c, NULL, NULL);
        puts("File read");
    }
    if (testFilesLevel > 1)
    {
        MmsConnection_getFileDirectory(con, err, NULL, NULL, NULL, NULL);
        puts("Get file directory");

        MmsConnection_fileClose(con, err, c);
        puts("File close");
    }
    if (testFilesLevel > 2)
    {
        MmsConnection_fileRename(con, err, "fileName", "newName");
        puts("File rename");

        MmsConnection_obtainFile(con, err, "newName", "newName");
        puts("Obtain file");

        MmsConnection_fileDelete(con, err, "newName");
        puts("File delete");
    }

    if (testJournalsLevel > 0)
    {
        res = MmsConnection_getDomainJournals(con, err, dom);
        puts("Get domain journals");
        if (err != MMS_ERROR_NONE)
        {
            puts("Error getting domain journals");
            jour = NULL;
        }
        else
        {
            jour = (char *)LinkedList_getData(res);
        }
        if (jour == NULL)
        {
            jour = "journ";
        }
        printf("Got journal name:%s\n", jour);
    }
    if (testJournalsLevel > 1)
    {
        MmsConnection_readJournalTimeRange(con, err, dom, jour, MmsValue_newBinaryTime(true), MmsValue_newBinaryTime(false), (bool *)&c);
        puts("Read journal time range");
    }
    if (testJournalsLevel > 2)
    {
        MmsConnection_readJournalStartAfter(con, err, dom, jour, MmsValue_newBinaryTime(true), MmsValue_newOctetString(4, 4), (bool *)&c);
        puts("Read journal start after");
    }

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

    int testIOLevel = 0;
    int testArraysLevel = 0;
    int testAdvancedLevel = 0;
    int testFilesLevel = 0;
    int testJournalsLevel = 0;
    int testQueryLevel = 0;

    int preset = 0;

    int coverage = 0;
    int c;

    while ((c = getopt(argc, argv, "mh:p:c:j:a:f:i:d:q:e:")) != -1)
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
        case 'c':
            coverage = atoi(optarg);
            break;
        case 'j':
            testJournalsLevel = atoi(optarg);
            break;
        case 'a':
            testArraysLevel = atoi(optarg);
            break;
        case 'f':
            testFilesLevel = atoi(optarg);
            break;
        case 'i':
            testIOLevel = atoi(optarg);
            break;
        case 'd':
            testAdvancedLevel = atoi(optarg);
            break;
        case 'q':
            testQueryLevel = atoi(optarg);
            break;
        case 'e':
            preset = atoi(optarg);
            switch (preset)
            {
            case 0:
                puts("Basic coverage selected: 4 seeds.");
                testIOLevel = 1;
                testArraysLevel = 0;
                testFilesLevel = 0;
                testJournalsLevel = 0;
                testAdvancedLevel = 0;
                testQueryLevel = 0;
                break;
            case 1:
                puts("Low coverage selected: 10 seeds.");
                testIOLevel = 1;
                testArraysLevel = 1;
                testFilesLevel = 0;
                testJournalsLevel = 0;
                testAdvancedLevel = 0;
                testQueryLevel = 1;
                break;
            case 2:
                puts("Medium coverage selected. 16 seeds.");
                testIOLevel = 2;
                testArraysLevel = 1;
                testFilesLevel = 1;
                testJournalsLevel = 0;
                testAdvancedLevel = 0;
                testQueryLevel = 2;
                break;
            case 3:
                puts("High coverage selected. 28 seeds.");
                testIOLevel = 3;
                testArraysLevel = 2;
                testFilesLevel = 2;
                testJournalsLevel = 1;
                testAdvancedLevel = 2;
                testQueryLevel = 3;
                break;
            case 4:
                puts("Full coverage selected. 38 seeds.");
                testIOLevel = 5;
                testArraysLevel = 5;
                testFilesLevel = 5;
                testJournalsLevel = 5;
                testAdvancedLevel = 5;
                testQueryLevel = 5;
                break;
            }
            break;

        default:
            print_help();
            return 0;
        }
    }
    if (testAdvancedLevel == 0)
    {
        testAdvancedLevel = coverage;
    }
    if (testQueryLevel == 0)
    {
        testQueryLevel = coverage;
    }
    if (testArraysLevel == 0)
    {
        testArraysLevel = coverage;
    }
    if (testFilesLevel == 0)
    {
        testFilesLevel = coverage;
    }
    if (testJournalsLevel == 0)
    {
        testJournalsLevel = coverage;
    }
    if (testIOLevel == 0)
    {
        testIOLevel = coverage;
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
        test(con, testJournalsLevel, testArraysLevel, testFilesLevel, testIOLevel, testAdvancedLevel, testQueryLevel);
    }
    MmsConnection_destroy(con);

    return returnCode;
}
