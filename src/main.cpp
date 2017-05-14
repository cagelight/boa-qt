#include <QApplication>

#include "boamainwin.hpp"
#include "boastuff.hpp"

int main(int argc, char * * argv) {
	QApplication app {argc, argv};
	BoaMainWin mwin {};
	mwin.show();
	auto rcode = app.exec();
	boa::cleanup();
	return rcode;
}
