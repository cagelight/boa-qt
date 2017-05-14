#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QSpinBox>
#include <QCheckBox>

class BoaTable : public QTableWidget {
	Q_OBJECT
public:
	BoaTable(QWidget * parent = nullptr);
	~BoaTable();
public slots:
	void addRow();
	void remRow();
	void load(QString, QString, QString);
	void save(QString, QString, QString);
};

class BoaView : public QWidget {
	Q_OBJECT
public:
	BoaView(QWidget * parent = nullptr);
	virtual ~BoaView();
protected:
	BoaTable * tb = nullptr;
protected slots:
	void intLoad();
	void intSave();
	void intHash();
	void intKeygen();
	void intEncrypt();
	void intDecrypt();
private:
	QLineEdit * keyEdit = nullptr;
	QLineEdit * hashEdit = nullptr;
	QLineEdit * cipherEdit = nullptr;
	QTextEdit * inputEdit = nullptr;
	QTextEdit * outputEdit = nullptr;
	QSpinBox * keygenCharCount = nullptr;
	QLineEdit * keygenSpecial = nullptr;
	QCheckBox * keygenCBUppercase = nullptr;
	QCheckBox * keygenCBLowercase = nullptr;
	QCheckBox * keygenCBNumeric = nullptr;
signals:
	void doLoad(QString, QString, QString);
	void doSave(QString, QString, QString);
};
