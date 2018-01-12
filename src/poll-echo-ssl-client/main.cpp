/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#include <QCoreApplication>
#include "poll_client.h"

#include <unistd.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    while (true) {
        PollClient poll_c;
        //poll_c.ConnectToServer("localhost", 12346);
        poll_c.ConnectToServer("mailgate.filoxeni.com", 12346);
        sleep(1);
    }

    return a.exec();
}
