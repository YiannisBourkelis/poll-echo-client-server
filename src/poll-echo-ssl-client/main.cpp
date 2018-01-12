#include <QCoreApplication>
#include "poll_client.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    PollClient poll_c;
    poll_c.ConnectToServer("localhost", 12346);

    return a.exec();
}
