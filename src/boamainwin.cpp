#include "boamainwin.hpp"
#include "boaview.hpp"

#include <QtWidgets>

BoaMainWin::BoaMainWin() : QWidget {nullptr} {
	QVBoxLayout * topl = new QVBoxLayout {this};
	BoaView * blw = new BoaView {this};
	topl->addWidget(blw);
}


BoaMainWin::~BoaMainWin() {
	
}
