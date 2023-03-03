#include "test.h"
#include <stdio.h>
#include <stdlib.h>




int main (int argc, char * argv[])
{

    if(argc < 2)
    {
        printf("invalid parameters\n");
        exit(0);
    }

    int option = atoi(argv[1]);

    switch (option)
    
    {

    case 0:

     //   TEST_01();
      //  TEST_02();
     //   TEST_03();
        TEST_04();

        break;
    
    default:
        printf("invalid option !!\n");
        break;
    }
    



    return 0;
}