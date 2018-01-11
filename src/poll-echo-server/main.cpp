#include <QCoreApplication>
#include "poll_server.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    PollServer pollserver;
    pollserver.start();

    return a.exec();
}
