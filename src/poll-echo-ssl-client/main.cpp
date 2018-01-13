/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#include <QCoreApplication>
#include "poll_client.h"

#include <qthread.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    while (true) {
        PollClient poll_c;
        poll_c.ConnectToServer("localhost", 12348, PollClient::IPv6);
        //poll_c.ConnectToServer("mailgate.filoxeni.com", 12346, PollClient::IPv4);
        QThread::msleep(1000);
    }

    return a.exec();
}
