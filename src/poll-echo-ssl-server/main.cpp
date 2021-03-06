/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#include <QCoreApplication>
#include "poll_server.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    PollServer pollserver;
    pollserver.start(12346, PollServer::IPv4);

    return a.exec();
}
