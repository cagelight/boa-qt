#include "boaview.hpp"

#include <QtWidgets>
#include <set>

#include "boastuff.hpp"

BoaTable::BoaTable(QWidget * parent) : QTableWidget(0, 5, parent) {
	this->setMinimumSize(800, 400);
	this->setHorizontalHeaderLabels({"Site", "Username", "Email", "Password", "Additional Info"});
	this->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
	this->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
	this->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
	this->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
	this->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
	this->setSizePolicy({QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding});
}

BoaTable::~BoaTable() {
	
}

void BoaTable::addRow() {
	insertRow(rowCount());
}

void BoaTable::remRow() {
	std::set<int, std::greater<int>> rows;
	for (QModelIndex & mi : selectedIndexes()) {
		rows.insert(mi.row());
	}
	for (int i : rows) {
		this->removeRow(i);
	}
}

void BoaTable::load(QString key, QString hash_func, QString cipher_func) {
	if (key.isEmpty() || hash_func.isEmpty() || cipher_func.isEmpty()) return;
	
	QString loadF = QFileDialog::getOpenFileName(this);
	if (loadF.isEmpty()) return;
	
	QFile f {loadF};
	f.open(QIODevice::ReadOnly);
	QByteArray qdata {f.readAll()};
	
	boa::binary_data data {qdata.begin(), qdata.end()};
	boa::array rows;
	try {
		rows = boa::from_data(key.toStdString(), hash_func.toStdString(), cipher_func.toStdString(), data);
		std::sort(rows.begin(), rows.end(), [](boa::array::value_type const & a, boa::array::value_type const & b){ return boa::entry::compare(a, b); });
	} catch (std::exception & err) {
		QMessageBox::critical(this, "ERROR", QString("FAILED TO LOAD:\n%1").arg(err.what()));
		return;
	}
	while (this->rowCount()) this->removeRow(0);
	int i = 0;
	for (boa::entry const & e : rows) {
		this->addRow();
		this->setItem(i, 0, new QTableWidgetItem {QString::fromStdString(e.name)});
		this->setItem(i, 1, new QTableWidgetItem {QString::fromStdString(e.username)});
		this->setItem(i, 2, new QTableWidgetItem {QString::fromStdString(e.email)});
		this->setItem(i, 3, new QTableWidgetItem {QString::fromStdString(e.password)});
		this->setItem(i, 4, new QTableWidgetItem {QString::fromStdString(e.addinfo)});
		i++;
	}
}

void BoaTable::save(QString key, QString hash_func, QString cipher_func) {
	if (key.isEmpty() || hash_func.isEmpty() || cipher_func.isEmpty()) return;
	
	QString saveF = QFileDialog::getSaveFileName(this);
	if (saveF.isEmpty()) return;

	boa::array rows {};
	for (int i = 0; i < this->rowCount(); i++) {
		boa::entry cur_ent {};
		QTableWidgetItem * temp;
		 
		temp = this->item(i, 0);
		if (temp) cur_ent.name = temp->text().toStdString();
		
		temp = this->item(i, 1);
		if (temp) cur_ent.username = temp->text().toStdString();
		
		temp = this->item(i, 2);
		if (temp) cur_ent.email = temp->text().toStdString();
		
		temp = this->item(i, 3);
		if (temp) cur_ent.password = temp->text().toStdString();
		
		temp = this->item(i, 4);
		if (temp) cur_ent.addinfo = temp->text().toStdString();
		
		rows.push_back(cur_ent);
	}
	boa::binary_data data;
	try {
		data = boa::to_data(key.toStdString(), hash_func.toStdString(), cipher_func.toStdString(), rows);
	} catch (std::exception & err) {
		QMessageBox::critical(this, "ERROR", QString("FAILED TO SAVE:\n%1").arg(err.what()));
		return;
	}
	QByteArray qdata {reinterpret_cast<char const *>(data.data()), static_cast<int>(data.size())};
	
	QFile f {saveF};
	f.open(QIODevice::WriteOnly);
	f.write(qdata);
}

QList<QTableWidgetItem *> BoaTable::find(QString str) {
	QList<QTableWidgetItem *> ret {};
	for (int i = 0; i < rowCount(); i++) {
		QTableWidgetItem * item2 = item(i, 0);
		if (item2->text().contains(str, Qt::CaseInsensitive)) ret.append(item2);
	}
	return ret;
}

BoaView::BoaView(QWidget * parent) : QWidget(parent) {
	QGridLayout * topl = new QGridLayout {this};
	topl->setMargin(0);
	int current_row = 0;
	
	QHBoxLayout * crypt_layout = new QHBoxLayout {};
	keyEdit = new QLineEdit("", this);
	keyEdit->setEchoMode(QLineEdit::Password);
	hashEdit = new QLineEdit("SHA-3", this);
	cipherEdit = new QLineEdit("Threefish-512/EAX", this);
	crypt_layout->addWidget(new QLabel("Key:", this));
	crypt_layout->addWidget(keyEdit);
	crypt_layout->addWidget(new QLabel("Hash Func:", this));
	crypt_layout->addWidget(hashEdit);
	crypt_layout->addWidget(new QLabel("Cipher:", this));
	crypt_layout->addWidget(cipherEdit);
	topl->addLayout(crypt_layout, current_row++, 0, 1, 2);
	
	QPushButton * loadB = new QPushButton("Load", this);
	topl->addWidget(loadB, current_row, 0, 1, 1);
	
	QPushButton * saveB = new QPushButton("Save", this);
	topl->addWidget(saveB, current_row++, 1, 1, 1);
	
	QHBoxLayout * findLayout = new QHBoxLayout {};
	QLabel * findLabel = new QLabel {"Find: ", this};
	findEdit = new QLineEdit {this};
	QPushButton * findNextB = new QPushButton {"Next", this};
	QPushButton * findPrevB = new QPushButton {"Prev", this};
	findLayout->addWidget(findLabel);
	findLayout->addWidget(findEdit);
	findLayout->addWidget(findNextB);
	findLayout->addWidget(findPrevB);
	topl->addLayout(findLayout, current_row++, 0, 1, 2);
	
	tb = new BoaTable(this);
	
	topl->addWidget(tb, current_row++, 0, 1, 2);
	
	QPushButton * addB = new QPushButton("Add", this);
	topl->addWidget(addB, current_row, 0, 1, 1);
	
	QPushButton * remB = new QPushButton("Remove", this);
	topl->addWidget(remB, current_row++, 1, 1, 1);
	
	inputEdit = new QTextEdit(this);
	outputEdit = new QTextEdit(this);
	
	topl->addWidget(new QLabel("Input:", this), current_row++, 0, 1, 2);
	topl->addWidget(inputEdit, current_row++, 0, 1, 2);
	
	QHBoxLayout * utils1 = new QHBoxLayout {}; // Hash
	QPushButton * hashB = new QPushButton("Hash", this);
	
	utils1->addWidget(hashB);
	
	topl->addLayout(utils1, current_row++, 0, 1, 2);
	
	QHBoxLayout * utils2 = new QHBoxLayout {}; // Keygen
	keygenCharCount = new QSpinBox(this);
	keygenCharCount->setMinimum(1);
	keygenCharCount->setMaximum(static_cast<int>(long(1<<31) - 1));
	keygenCharCount->setValue(32);
	keygenSpecial = new QLineEdit(this);
	keygenCBUppercase = new QCheckBox(this);
	keygenCBLowercase = new QCheckBox(this);
	keygenCBNumeric = new QCheckBox(this);
	QPushButton * keygenB = new QPushButton("KeyGen", this);
	
	utils2->addWidget(keygenCharCount);
	utils2->addWidget(new QLabel("Uppercase:", this));
	utils2->addWidget(keygenCBUppercase);
	utils2->addWidget(new QLabel("Lowercase:", this));
	utils2->addWidget(keygenCBLowercase);
	utils2->addWidget(new QLabel("Numbers:", this));
	utils2->addWidget(keygenCBNumeric);
	utils2->addWidget(new QLabel("Additional Chars:", this));
	utils2->addWidget(keygenSpecial);
	utils2->addWidget(keygenB);
	
	topl->addLayout(utils2, current_row++, 0, 1, 2);
	
	topl->addWidget(new QLabel("Output:", this), current_row++, 0, 1, 2);
	topl->addWidget(outputEdit, current_row++, 0, 1, 2);
	
	connect(loadB, SIGNAL(clicked()), this, SLOT(intLoad()));
	connect(saveB, SIGNAL(clicked()), this, SLOT(intSave()));
	connect(this, SIGNAL(doLoad(QString, QString, QString)), tb, SLOT(load(QString, QString, QString)));
	connect(this, SIGNAL(doSave(QString, QString, QString)), tb, SLOT(save(QString, QString, QString)));
	connect(addB, SIGNAL(clicked()), tb, SLOT(addRow()));
	connect(remB, SIGNAL(clicked()), tb, SLOT(remRow()));
	connect(hashB, SIGNAL(clicked()), this, SLOT(intHash()));
	connect(keygenB, SIGNAL(clicked()), this, SLOT(intKeygen()));
	
	connect(findEdit, &QLineEdit::textChanged, this, [this](){
		findCur = 0;
		auto items = tb->find(findEdit->text());
		if (items.size()) tb->setCurrentItem(items[0]);
	});
}

BoaView::~BoaView() {
	
}

void BoaView::intLoad() {
	emit doLoad(keyEdit->text(), hashEdit->text(), cipherEdit->text());
}

void BoaView::intSave() {
	emit doSave(keyEdit->text(), hashEdit->text(), cipherEdit->text());
}

void BoaView::intHash() {
	QString input = inputEdit->toPlainText();
	if (input.isEmpty()) return;
	try {
		outputEdit->setText(QString::fromStdString(boa::hex(boa::hash(input.toStdString(), hashEdit->text().toStdString()))));
	} catch (std::exception & e) {
		outputEdit->setText(QString("ERROR: %1").arg(e.what()));
	}
}

static constexpr char alphabet_upper [] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };
static constexpr char alphabet_lower [] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z' };
static constexpr char numeric [] = { '0','1','2','3','4','5','6','7','8','9' };

void BoaView::intKeygen() {
	std::vector<char> pool {};
	if (keygenCBUppercase->isChecked()) pool.insert(pool.end(), alphabet_upper, &alphabet_upper[sizeof(alphabet_upper)]);
	if (keygenCBLowercase->isChecked()) pool.insert(pool.end(), alphabet_lower, &alphabet_lower[sizeof(alphabet_lower)]);
	if (keygenCBNumeric->isChecked()) pool.insert(pool.end(), numeric, &numeric[sizeof(numeric)]);
	for (char c : keygenSpecial->text().toStdString()) pool.push_back(c);
	if (!pool.size()) return;
	try {
		outputEdit->setText(QString::fromStdString(boa::keygen(keygenCharCount->value(), pool)));
	} catch (std::exception & e) {
		outputEdit->setText(QString("ERROR: %1").arg(e.what()));
	}
}

void BoaView::intEncrypt() {
	
}

void BoaView::intDecrypt() {
	
}
