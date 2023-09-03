// Copyright 2022-2023 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "MumbleServerIce.h"

#include "Ban.h"
#include "Channel.h"
#include "ChannelListenerManager.h"
#include "Group.h"
#include "Meta.h"
#include "MumbleServer.h"
#include "QtUtils.h"
#include "Server.h"
#include "ServerDB.h"
#include "ServerUser.h"
#include "User.h"
#include "Utils.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QSettings>
#include <QtCore/QStack>

#include <openssl/err.h>

#include <Ice/Ice.h>
#include <Ice/LocalObjectF.h>
#include <Ice/SliceChecksums.h>
#include <IceUtil/IceUtil.h>

#include <limits>

using namespace std;
using namespace MumbleServer;

static MumbleServerIce *mi = nullptr;
static Ice::ObjectPtr iopServer;
static Ice::PropertiesPtr ippProperties;

void IceParse(int &argc, char *argv[]) {
	ippProperties = Ice::createProperties(argc, argv);
}

void IceStart() {
	mi = new MumbleServerIce();
}

void IceStop() {
	delete mi;
	mi = nullptr;
}

/// Remove all NUL bytes from |s|.
static std::string iceRemoveNul(std::string s) {
	std::vector< char > newstr;
	for (size_t i = 0; i < s.size(); i++) {
		char c = s.at(i);
		if (c == 0) {
			continue;
		}
		newstr.push_back(s.at(i));
	}
	return std::string(newstr.begin(), newstr.end());
}

/// Marshall the QString |s| to be safe for use on
/// the wire in Ice messages, parameters
/// and return values.
///
/// What happens under the hood is that the string
/// is converted to UTF-8, and all NUL bytes are
/// removed.
static std::string iceString(const QString &s) {
	return iceRemoveNul(u8(s));
}

/// Convert the bytes in std::string to base64 using the
/// base64 alphabet from RFC 2045.
///
/// The size of the string may not exceed sizeof(int).
/// If the function is passed a string bigger than that,
/// it will return an empty string.
static std::string iceBase64(const std::string &s) {
	if (s.size() > static_cast< size_t >(std::numeric_limits< int >::max())) {
		return std::string();
	}

	QByteArray ba(s.data(), static_cast< int >(s.size()));
	QByteArray ba64 = ba.toBase64();

	return std::string(ba64.data(), static_cast< size_t >(ba64.size()));
}

static void logToLog(const ServerDB::LogRecord &r, ::MumbleServer::LogEntry &le) {
	le.timestamp = r.first;
	le.txt       = iceString(r.second);
}

static void userToUser(const ::User *p, ::MumbleServer::User &mp) {
	mp.session         = p->uiSession;
	mp.userid          = p->iId;
	mp.name            = iceString(p->qsName);
	mp.mute            = p->bMute;
	mp.deaf            = p->bDeaf;
	mp.suppress        = p->bSuppress;
	mp.recording       = p->bRecording;
	mp.prioritySpeaker = p->bPrioritySpeaker;
	mp.selfMute        = p->bSelfMute;
	mp.selfDeaf        = p->bSelfDeaf;
	mp.channel         = p->cChannel->iId;
	mp.comment         = iceString(p->qsComment);

	const ServerUser *u = static_cast< const ServerUser * >(p);
	mp.onlinesecs       = u->bwr.onlineSeconds();
	mp.bytespersec      = u->bwr.bandwidth();
	mp.version2         = u->m_version;
	mp.version          = Version::toLegacyVersion(u->m_version);
	mp.release          = iceString(u->qsRelease);
	mp.os               = iceString(u->qsOS);
	mp.osversion        = iceString(u->qsOSVersion);
	mp.identity         = iceString(u->qsIdentity);
	mp.context          = iceBase64(u->ssContext);
	mp.idlesecs         = u->bwr.idleSeconds();
	mp.udpPing          = u->dUDPPingAvg;
	mp.tcpPing          = u->dTCPPingAvg;

#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
	mp.tcponly = u->aiUdpFlag.loadRelaxed() == 0;
#else
	// Qt 5.14 introduced QAtomicInteger::loadRelaxed() which deprecates QAtomicInteger::load()
	mp.tcponly = u->aiUdpFlag.load() == 0;
#endif

	::MumbleServer::NetAddress addr(16, 0);
	const Q_IPV6ADDR &a = u->haAddress.qip6;
	for (int i = 0; i < 16; ++i)
		addr[i] = a[i];

	mp.address = addr;
}

static void channelToChannel(const ::Channel *c, ::MumbleServer::Channel &mc) {
	mc.id          = c->iId;
	mc.name        = iceString(c->qsName);
	mc.parent      = c->cParent ? c->cParent->iId : -1;
	mc.description = iceString(c->qsDesc);
	mc.position    = c->iPosition;
	mc.links.clear();
	foreach (::Channel *chn, c->qsPermLinks)
		mc.links.push_back(chn->iId);
	mc.temporary = c->bTemporary;
}

static void ACLtoACL(const ::ChanACL *acl, ::MumbleServer::ACL &ma) {
	ma.applyHere = acl->bApplyHere;
	ma.applySubs = acl->bApplySubs;
	ma.inherited = false;
	ma.userid    = acl->iUserId;
	ma.group     = iceString(acl->qsGroup);
	ma.allow     = acl->pAllow;
	ma.deny      = acl->pDeny;
}

static void groupToGroup(const ::Group *g, ::MumbleServer::Group &mg) {
	mg.name        = iceString(g->qsName);
	mg.inherit     = g->bInherit;
	mg.inheritable = g->bInheritable;
	mg.add.clear();
	mg.remove.clear();
	mg.members.clear();
}

static void banToBan(const ::Ban &b, ::MumbleServer::Ban &mb) {
	::MumbleServer::NetAddress addr(16, 0);
	const Q_IPV6ADDR &a = b.haAddress.qip6;
	for (int i = 0; i < 16; ++i)
		addr[i] = a[i];

	mb.address  = addr;
	mb.bits     = b.iMask;
	mb.name     = iceString(b.qsUsername);
	mb.hash     = iceString(b.qsHash);
	mb.reason   = iceString(b.qsReason);
	mb.start    = b.qdtStart.toLocalTime().toTime_t();
	mb.duration = b.iDuration;
}

static void banToBan(const ::MumbleServer::Ban &mb, ::Ban &b) {
	if (mb.address.size() != 16)
		for (int i = 0; i < 16; ++i)
			b.haAddress.qip6[i] = 0;
	else
		for (int i = 0; i < 16; ++i)
			b.haAddress.qip6[i] = mb.address[i];
	b.iMask      = mb.bits;
	b.qsUsername = u8(mb.name);
	b.qsHash     = u8(mb.hash);
	b.qsReason   = u8(mb.reason);
	b.qdtStart   = QDateTime::fromTime_t(static_cast< quint32 >(mb.start)).toUTC();
	b.iDuration  = mb.duration;
}

static void infoToInfo(const QMap< int, QString > &info, ::MumbleServer::UserInfoMap &im) {
	QMap< int, QString >::const_iterator i;
	for (i = info.constBegin(); i != info.constEnd(); ++i)
		im[static_cast<::MumbleServer::UserInfo >(i.key())] = iceString(i.value());
}

static void infoToInfo(const ::MumbleServer::UserInfoMap &im, QMap< int, QString > &info) {
	::MumbleServer::UserInfoMap::const_iterator i;
	for (i = im.begin(); i != im.end(); ++i)
		info.insert(static_cast<int>((*i).first), u8((*i).second));
}

static void textmessageToTextmessage(const ::TextMessage &tm, ::MumbleServer::TextMessage &tmdst) {
	tmdst.text = iceString(tm.qsText);

	foreach (unsigned int i, tm.qlSessions)
		tmdst.sessions.push_back(i);

	foreach (unsigned int i, tm.qlChannels)
		tmdst.channels.push_back(i);

	foreach (unsigned int i, tm.qlTrees)
		tmdst.trees.push_back(i);
}

class ServerLocator : public virtual Ice::ServantLocator {
public:
	virtual std::shared_ptr< Ice::Object > locate(const Ice::Current &, std::shared_ptr< void > &cookie);
	virtual void finished(const Ice::Current &, const std::shared_ptr< Ice::Object > &, const std::shared_ptr< void > &){};
	virtual void deactivate(const std::string &){};
};

MumbleServerIce::MumbleServerIce() {
	count = 0;

	if (meta->mp.qsIceEndpoint.isEmpty())
		return;

	Ice::PropertiesPtr ipp = Ice::createProperties();

	::Meta::mp.qsSettings->beginGroup("Ice");
	foreach (const QString &v, ::Meta::mp.qsSettings->childKeys()) {
		ipp->setProperty(iceString(v), iceString(::Meta::mp.qsSettings->value(v).toString()));
	}
	::Meta::mp.qsSettings->endGroup();

	Ice::PropertyDict props = ippProperties->getPropertiesForPrefix("");
	Ice::PropertyDict::iterator i;
	for (i = props.begin(); i != props.end(); ++i) {
		ipp->setProperty((*i).first, (*i).second);
	}
	ipp->setProperty("Ice.ImplicitContext", "Shared");

	Ice::InitializationData idd;
	idd.properties = ipp;

	try {
		communicator = Ice::initialize(idd);
		if (!meta->mp.qsIceSecretWrite.isEmpty()) {
			::Ice::ImplicitContextPtr impl = communicator->getImplicitContext();
			if (impl)
				impl->put("secret", iceString(meta->mp.qsIceSecretWrite));
		}
		adapter   = communicator->createObjectAdapterWithEndpoints("Mumble Server", qPrintable(meta->mp.qsIceEndpoint));
		MetaPtr m = std::make_shared<MetaI>();
		MetaPrxPtr mprx = Ice::checkedCast<MetaPrx>(adapter->add(m, Ice::stringToIdentity("Meta")));
		std::shared_ptr< ServerLocator > locator = std::make_shared< ServerLocator >();
		adapter->addServantLocator(locator, "s");

		iopServer = std::make_shared<ServerI>();

		adapter->activate();
		foreach (const Ice::EndpointPtr ep, mprx->ice_getEndpoints()) {
			qWarning("MumbleServerIce: Endpoint \"%s\" running", qPrintable(u8(ep->toString())));
		}

		meta->connectListener(this);
	} catch (Ice::Exception &e) {
#if ICE_INT_VERSION >= 30700
		qCritical("MumbleServerIce: Initialization failed: %s", qPrintable(u8(e.ice_id())));
#else
		qCritical("MumbleServerIce: Initialization failed: %s", qPrintable(u8(e.ice_name())));
#endif
	}
}

MumbleServerIce::~MumbleServerIce() {
	if (communicator) {
		communicator->shutdown();
		communicator->waitForShutdown();
		communicator->destroy();
		communicator = nullptr;
		qWarning("MumbleServerIce: Shutdown complete");
	}
	iopServer = nullptr;
}

void MumbleServerIce::customEvent(QEvent *evt) {
	if (evt->type() == EXEC_QEVENT)
		static_cast< ExecEvent * >(evt)->execute();
}

void MumbleServerIce::badMetaProxy(const ::MumbleServer::MetaCallbackPrxPtr &prx) {
	qCritical("Ice MetaCallback %s failed", qPrintable(QString::fromStdString(communicator->proxyToString(prx))));
	removeMetaCallback(prx);
}

void MumbleServerIce::badServerProxy(const ::MumbleServer::ServerCallbackPrxPtr &prx, const ::Server *server) {
	server->log(QString("Ice ServerCallback %1 failed").arg(QString::fromStdString(communicator->proxyToString(prx))));
	removeServerCallback(server, prx);
}

void MumbleServerIce::badAuthenticator(::Server *server) {
	server->disconnectAuthenticator(this);
	const ::MumbleServer::ServerAuthenticatorPrxPtr prx = qmServerAuthenticator.value(server->iServerNum);
	server->log(QString("Ice Authenticator %1 failed").arg(QString::fromStdString(communicator->proxyToString(prx))));
	removeServerAuthenticator(server);
	removeServerUpdatingAuthenticator(server);
}

void MumbleServerIce::addMetaCallback(const ::MumbleServer::MetaCallbackPrxPtr &prx) {
	if (!qlMetaCallbacks.contains(prx)) {
		qWarning("Added Ice MetaCallback %s", qPrintable(QString::fromStdString(communicator->proxyToString(prx))));
		qlMetaCallbacks.append(prx);
	}
}

void MumbleServerIce::removeMetaCallback(const ::MumbleServer::MetaCallbackPrxPtr &prx) {
	if (qlMetaCallbacks.removeAll(prx)) {
		qWarning("Removed Ice MetaCallback %s", qPrintable(QString::fromStdString(communicator->proxyToString(prx))));
	}
}

void MumbleServerIce::addServerCallback(const ::Server *server, const ::MumbleServer::ServerCallbackPrxPtr &prx) {
	QList<::MumbleServer::ServerCallbackPrxPtr > &cbList = qmServerCallbacks[server->iServerNum];

	if (!cbList.contains(prx)) {
		server->log(
			QString("Added Ice ServerCallback %1").arg(QString::fromStdString(communicator->proxyToString(prx))));
		cbList.append(prx);
	}
}

void MumbleServerIce::removeServerCallback(const ::Server *server, const ::MumbleServer::ServerCallbackPrxPtr& prx) {
	if (qmServerCallbacks[server->iServerNum].removeAll(prx)) {
		server->log(
			QString("Removed Ice ServerCallback %1").arg(QString::fromStdString(communicator->proxyToString(prx))));
	}
}

void MumbleServerIce::removeServerCallbacks(const ::Server *server) {
	if (qmServerCallbacks.contains(server->iServerNum)) {
		server->log(QString("Removed all Ice ServerCallbacks"));
		qmServerCallbacks.remove(server->iServerNum);
	}
}

void MumbleServerIce::addServerContextCallback(const ::Server *server, int session_id, const QString &action,
											   const ::MumbleServer::ServerContextCallbackPrxPtr &prx) {
	QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > &callbacks =
		qmServerContextCallbacks[server->iServerNum][session_id];

	if (!callbacks.contains(action) || callbacks[action] != prx) {
		server->log(QString("Added Ice ServerContextCallback %1 for session %2, action %3")
						.arg(QString::fromStdString(communicator->proxyToString(prx)))
						.arg(session_id)
						.arg(action));
		callbacks.insert(action, prx);
	}
}

const QMap< int, QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > >
	MumbleServerIce::getServerContextCallbacks(const ::Server *server) const {
	return qmServerContextCallbacks[server->iServerNum];
}

void MumbleServerIce::removeServerContextCallback(const ::Server *server, int session_id, const QString &action) {
	if (qmServerContextCallbacks[server->iServerNum][session_id].remove(action)) {
		server->log(QString("Removed Ice ServerContextCallback for session %1, action %2").arg(session_id).arg(action));
	}
}

void MumbleServerIce::setServerAuthenticator(const ::Server *server,
											 const ::MumbleServer::ServerAuthenticatorPrxPtr &prx) {
	if (prx != qmServerAuthenticator[server->iServerNum]) {
		server->log(
			QString("Set Ice Authenticator to %1").arg(QString::fromStdString(communicator->proxyToString(prx))));
		qmServerAuthenticator[server->iServerNum] = prx;
	}
}

const ::MumbleServer::ServerAuthenticatorPrxPtr MumbleServerIce::getServerAuthenticator(const ::Server *server) const {
	return qmServerAuthenticator[server->iServerNum];
}

void MumbleServerIce::removeServerAuthenticator(const ::Server *server) {
	if (qmServerAuthenticator.remove(server->iServerNum)) {
		server->log(QString("Removed Ice Authenticator %1")
						.arg(QString::fromStdString(communicator->proxyToString(getServerAuthenticator(server)))));
	}
}

void MumbleServerIce::setServerUpdatingAuthenticator(const ::Server *server,
													 const ::MumbleServer::ServerUpdatingAuthenticatorPrxPtr &prx) {
	if (prx != qmServerUpdatingAuthenticator[server->iServerNum]) {
		server->log(QString("Set Ice UpdatingAuthenticator to %1")
						.arg(QString::fromStdString(communicator->proxyToString(prx))));
		qmServerUpdatingAuthenticator[server->iServerNum] = prx;
	}
}

const ::MumbleServer::ServerUpdatingAuthenticatorPrxPtr
	MumbleServerIce::getServerUpdatingAuthenticator(const ::Server *server) const {
	return qmServerUpdatingAuthenticator[server->iServerNum];
}

void MumbleServerIce::removeServerUpdatingAuthenticator(const ::Server *server) {
	if (qmServerUpdatingAuthenticator.contains(server->iServerNum)) {
		server->log(
			QString("Removed Ice UpdatingAuthenticator %1")
				.arg(QString::fromStdString(communicator->proxyToString(getServerUpdatingAuthenticator(server)))));
		qmServerUpdatingAuthenticator.remove(server->iServerNum);
	}
}

static ServerPrxPtr idToProxy(int id, const Ice::ObjectAdapterPtr &adapter) {
	Ice::Identity ident;
	ident.category = "s";
	ident.name     = iceString(QString::number(id));

	return Ice::uncheckedCast<ServerPrx>(adapter->createProxy(ident));
}

void MumbleServerIce::started(::Server *s) {
	s->connectListener(mi);
	connect(s, SIGNAL(contextAction(const User *, const QString &, unsigned int, int)), this,
			SLOT(contextAction(const User *, const QString &, unsigned int, int)));

	const QList<::MumbleServer::MetaCallbackPrxPtr > &qlList = qlMetaCallbacks;

	if (qlList.isEmpty())
		return;

	foreach (const ::MumbleServer::MetaCallbackPrxPtr &prx, qlList) {
		try {
			prx->started(idToProxy(s->iServerNum, adapter));
		} catch (...) {
			badMetaProxy(prx);
		}
	}
}

void MumbleServerIce::stopped(::Server *s) {
	removeServerCallbacks(s);
	removeServerAuthenticator(s);
	removeServerUpdatingAuthenticator(s);

	const QList<::MumbleServer::MetaCallbackPrxPtr > &qmList = qlMetaCallbacks;

	if (qmList.isEmpty())
		return;

	foreach (const ::MumbleServer::MetaCallbackPrxPtr &prx, qmList) {
		try {
			prx->stopped(idToProxy(s->iServerNum, adapter));
		} catch (...) {
			badMetaProxy(prx);
		}
	}
}

void MumbleServerIce::userConnected(const ::User *p) {
	::Server *s = qobject_cast<::Server * >(sender());

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::User mp;
	userToUser(p, mp);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->userConnected(mp);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::userDisconnected(const ::User *p) {
	::Server *s = qobject_cast<::Server * >(sender());

	qmServerContextCallbacks[s->iServerNum].remove(p->uiSession);

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::User mp;
	userToUser(p, mp);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->userDisconnected(mp);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::userStateChanged(const ::User *p) {
	::Server *s = qobject_cast<::Server * >(sender());

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::User mp;
	userToUser(p, mp);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->userStateChanged(mp);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::userTextMessage(const ::User *p, const ::TextMessage &message) {
	::Server *s = qobject_cast<::Server * >(sender());

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::User mp;
	userToUser(p, mp);

	::MumbleServer::TextMessage textMessage;
	textmessageToTextmessage(message, textMessage);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->userTextMessage(mp, textMessage);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::channelCreated(const ::Channel *c) {
	::Server *s = qobject_cast<::Server * >(sender());

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::Channel mc;
	channelToChannel(c, mc);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->channelCreated(mc);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::channelRemoved(const ::Channel *c) {
	::Server *s = qobject_cast<::Server * >(sender());

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::Channel mc;
	channelToChannel(c, mc);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->channelRemoved(mc);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::channelStateChanged(const ::Channel *c) {
	::Server *s = qobject_cast<::Server * >(sender());

	const QList<::MumbleServer::ServerCallbackPrxPtr > &qmList = qmServerCallbacks[s->iServerNum];

	if (qmList.isEmpty())
		return;

	::MumbleServer::Channel mc;
	channelToChannel(c, mc);

	foreach (const ::MumbleServer::ServerCallbackPrxPtr &prx, qmList) {
		try {
			prx->channelStateChanged(mc);
		} catch (...) {
			badServerProxy(prx, s);
		}
	}
}

void MumbleServerIce::contextAction(const ::User *pSrc, const QString &action, unsigned int session, int iChannel) {
	::Server *s = qobject_cast<::Server * >(sender());

	QMap< int, QMap< int, QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > > > &qmAll =
		qmServerContextCallbacks;
	if (!qmAll.contains(s->iServerNum))
		return;

	QMap< int, QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > > &qmServer = qmAll[s->iServerNum];
	if (!qmServer.contains(pSrc->uiSession))
		return;

	QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > &qmUser = qmServer[pSrc->uiSession];
	if (!qmUser.contains(action))
		return;

	const ::MumbleServer::ServerContextCallbackPrxPtr &prx = qmUser[action];

	::MumbleServer::User mp;
	userToUser(pSrc, mp);

	try {
		prx->contextAction(iceString(action), mp, session, iChannel);
	} catch (...) {
		s->log(QString("Ice ServerContextCallback %1 for session %2, action %3 failed")
				   .arg(QString::fromStdString(communicator->proxyToString(prx)))
				   .arg(pSrc->uiSession)
				   .arg(action));
		removeServerContextCallback(s, pSrc->uiSession, action);

		// Remove clientside entry
		MumbleProto::ContextActionModify mpcam;
		mpcam.set_action(iceString(action));
		mpcam.set_operation(MumbleProto::ContextActionModify_Operation_Remove);
		ServerUser *su = s->qhUsers.value(session);
		if (su)
			s->sendMessage(su, mpcam);
	}
}

void MumbleServerIce::idToNameSlot(QString &name, int id) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerAuthenticatorPrxPtr prx = getServerAuthenticator(server);
	try {
		name = u8(prx->idToName(id));
	} catch (...) {
		badAuthenticator(server);
	}
}
void MumbleServerIce::idToTextureSlot(QByteArray &qba, int id) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerAuthenticatorPrxPtr prx = getServerAuthenticator(server);
	try {
		const ::MumbleServer::Texture &tex = prx->idToTexture(id);

		qba.resize(static_cast< int >(tex.size()));
		char *ptr = qba.data();
		for (unsigned int i = 0; i < tex.size(); ++i)
			ptr[i] = tex[i];
	} catch (...) {
		badAuthenticator(server);
	}
}

void MumbleServerIce::nameToIdSlot(int &id, const QString &name) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerAuthenticatorPrxPtr prx = getServerAuthenticator(server);
	try {
		id = prx->nameToId(iceString(name));
	} catch (...) {
		badAuthenticator(server);
	}
}

void MumbleServerIce::authenticateSlot(int &res, QString &uname, int sessionId,
									   const QList< QSslCertificate > &certlist, const QString &certhash,
									   bool certstrong, const QString &pw) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerAuthenticatorPrxPtr prx = getServerAuthenticator(server);
	::std::string newname;
	::MumbleServer::GroupNameList groups;
	::MumbleServer::CertificateList certs;

	certs.resize(certlist.size());
	for (int i = 0; i < certlist.size(); ++i) {
		::MumbleServer::CertificateDer der;
		QByteArray qba = certlist.at(i).toDer();
		der.resize(qba.size());
		const char *ptr = qba.constData();
		for (int j = 0; j < qba.size(); ++j)
			der[j] = ptr[j];
		certs[i] = der;
	}

	try {
		res =
			prx->authenticate(iceString(uname), iceString(pw), certs, iceString(certhash), certstrong, newname, groups);
	} catch (...) {
		badAuthenticator(server);
	}
	if (res >= 0) {
		if (newname.length() > 0)
			uname = u8(newname);
		QStringList qsl;
		foreach (const ::std::string &str, groups) { qsl << u8(str); }
		if (!qsl.isEmpty())
			server->setTempGroups(res, sessionId, nullptr, qsl);
	}
}

void MumbleServerIce::registerUserSlot(int &res, const QMap< int, QString > &info) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerUpdatingAuthenticatorPrxPtr prx = getServerUpdatingAuthenticator(server);
	if (!prx)
		return;

	::MumbleServer::UserInfoMap im;

	infoToInfo(info, im);
	try {
		res = prx->registerUser(im);
	} catch (...) {
		badAuthenticator(server);
	}
}

void MumbleServerIce::unregisterUserSlot(int &res, int id) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerUpdatingAuthenticatorPrxPtr prx = getServerUpdatingAuthenticator(server);
	if (!prx)
		return;
	try {
		res = prx->unregisterUser(id);
	} catch (...) {
		badAuthenticator(server);
	}
}

void MumbleServerIce::getRegistrationSlot(int &res, int id, QMap< int, QString > &info) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerUpdatingAuthenticatorPrxPtr prx = getServerUpdatingAuthenticator(server);
	if (!prx)
		return;

	::MumbleServer::UserInfoMap im;
	try {
		if (prx->getInfo(id, im)) {
			res = 1;
			infoToInfo(im, info);
		}
	} catch (...) {
		badAuthenticator(server);
		return;
	}
}

void MumbleServerIce::getRegisteredUsersSlot(const QString &filter, QMap< int, QString > &m) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerUpdatingAuthenticatorPrxPtr prx = getServerUpdatingAuthenticator(server);
	if (!prx)
		return;

	::MumbleServer::NameMap lst;

	try {
		lst = prx->getRegisteredUsers(iceString(filter));
	} catch (...) {
		badAuthenticator(server);
		return;
	}
	::MumbleServer::NameMap::const_iterator i;
	for (i = lst.begin(); i != lst.end(); ++i)
		m.insert((*i).first, u8((*i).second));
}

void MumbleServerIce::setInfoSlot(int &res, int id, const QMap< int, QString > &info) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerUpdatingAuthenticatorPrxPtr prx = getServerUpdatingAuthenticator(server);
	if (!prx)
		return;

	MumbleServer::UserInfoMap im;
	infoToInfo(info, im);

	try {
		res = prx->setInfo(id, im);
	} catch (...) {
		badAuthenticator(server);
	}
}

void MumbleServerIce::setTextureSlot(int &res, int id, const QByteArray &texture) {
	::Server *server = qobject_cast<::Server * >(sender());

	const ServerUpdatingAuthenticatorPrxPtr prx = getServerUpdatingAuthenticator(server);
	if (!prx)
		return;

	::MumbleServer::Texture tex;
	tex.resize(texture.size());
	const char *ptr = texture.constData();
	for (int i = 0; i < texture.size(); ++i)
		tex[i] = ptr[i];

	try {
		res = prx->setTexture(id, tex);
	} catch (...) {
		badAuthenticator(server);
	}
}

std::shared_ptr< Ice::Object > ServerLocator::locate(const Ice::Current &, std::shared_ptr< void > &) {
	return iopServer;
}

#define FIND_SERVER ::Server *server = meta->qhServers.value(server_id);

#define NEED_SERVER_EXISTS                                                     \
	FIND_SERVER                                                                \
	if (!server && !ServerDB::serverExists(server_id)) {                       \
		exception(std::make_exception_ptr(::Ice::ObjectNotExistException(__FILE__, __LINE__))); \
		return;                                                                \
	}

#define NEED_SERVER                                 \
	NEED_SERVER_EXISTS                              \
	if (!server) {                                  \
		exception(std::make_exception_ptr(ServerBootedException())); \
		return;                                     \
	}

#define NEED_PLAYER                                                   \
	ServerUser *user = server->qhUsers.value(session);                \
	if (!user) {                                                      \
		exception(std::make_exception_ptr(::MumbleServer::InvalidSessionException())); \
		return;                                                       \
	}

#define NEED_CHANNEL_VAR(x, y)                                        \
	x = server->qhChannels.value(y);                                  \
	if (!x) {                                                         \
		exception(std::make_exception_ptr(::MumbleServer::InvalidChannelException())); \
		return;                                                       \
	}

#define NEED_CHANNEL    \
	::Channel *channel; \
	NEED_CHANNEL_VAR(channel, channelid);

void ServerI::ice_ping(const Ice::Current &current) const {
	// This is executed in the ice thread.
	int server_id = u8(current.id.name).toInt();
	if (!ServerDB::serverExists(server_id))
		throw ::Ice::ObjectNotExistException(__FILE__, __LINE__);
}

#define ACCESS_Server_isRunning_READ
static void impl_Server_isRunning(std::function< void(bool returnValue) > response,
								  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;
	response(server != nullptr);
}

static void impl_Server_start(std::function< void() > response, std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;
	if (server)
		exception(std::make_exception_ptr(ServerBootedException()));
	else if (!meta->boot(server_id))
		exception(std::make_exception_ptr(ServerFailureException()));
	else
		response();
}

static void impl_Server_stop(std::function< void() > response, std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	meta->kill(server_id);
	response();
}

static void impl_Server_delete(std::function< void() > response, std::function< void(std::exception_ptr) > exception,
							   int server_id) {
	NEED_SERVER_EXISTS;
	if (server) {
		exception(std::make_exception_ptr(ServerBootedException()));
		return;
	}
	ServerDB::deleteServer(server_id);
	response();
}

static void impl_Server_addCallback(std::shared_ptr< ServerCallbackPrx > cbptr, std::function< void() > response,
									std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	try {
		const MumbleServer::ServerCallbackPrxPtr oneway =
			Ice::checkedCast < MumbleServer::ServerCallbackPrx>(cbptr->ice_oneway()->ice_connectionCached(false));
		mi->addServerCallback(server, oneway);
		response();
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
	}
}

static void impl_Server_removeCallback(std::shared_ptr< ServerCallbackPrx > cbptr, std::function< void() > response,
									   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	try {
		const MumbleServer::ServerCallbackPrxPtr oneway =
			Ice::uncheckedCast < MumbleServer::ServerCallbackPrx>(cbptr->ice_oneway()->ice_connectionCached(false));
		mi->removeServerCallback(server, oneway);
		response();
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
	}
}

static void impl_Server_setAuthenticator(std::shared_ptr< ServerAuthenticatorPrx > aptr,
										 std::function< void() > response,
										 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	if (mi->getServerAuthenticator(server))
		server->disconnectAuthenticator(mi);

	::MumbleServer::ServerAuthenticatorPrxPtr prx;

	try {
		prx = Ice::checkedCast<::MumbleServer::ServerAuthenticatorPrx>(aptr->ice_connectionCached(false)->ice_timeout(5000));
		const ::MumbleServer::ServerUpdatingAuthenticatorPrxPtr uprx =
			Ice::checkedCast<::MumbleServer::ServerUpdatingAuthenticatorPrx>(prx);

		mi->setServerAuthenticator(server, prx);
		if (uprx)
			mi->setServerUpdatingAuthenticator(server, uprx);
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
		return;
	}

	if (prx)
		server->connectAuthenticator(mi);

	response();
}

#define ACCESS_Server_id_READ
static void impl_Server_id(std::function< void(int returnValue) > response,
						   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;
	response(server_id);
}

#define ACCESS_Server_getConf_READ
static void impl_Server_getConf(std::string key, std::function< void(const std::string &returnValue) > response,
								std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;
	if (key == "key" || key == "passphrase")
		exception(std::make_exception_ptr(WriteOnlyException()));
	else
		response(iceString(ServerDB::getConf(server_id, u8(key)).toString()));
}

#define ACCESS_Server_getAllConf_READ
static void impl_Server_getAllConf(std::function< void(const ::MumbleServer::ConfigMap &returnValue) > response,
								   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;

	::MumbleServer::ConfigMap cm;

	QMap< QString, QString > values = ServerDB::getAllConf(server_id);
	QMap< QString, QString >::const_iterator i;
	for (i = values.constBegin(); i != values.constEnd(); ++i) {
		if (i.key() == "key" || i.key() == "passphrase")
			continue;
		cm[iceString(i.key())] = iceString(i.value());
	}
	response(cm);
}

static void impl_Server_setConf(std::string key, std::string value, std::function< void() > response,
								std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;
	QString k = u8(key);
	QString v = u8(value);
	ServerDB::setConf(server_id, k, v);
	if (server) {
		QWriteLocker wl(&server->qrwlVoiceThread);
		server->setLiveConf(k, v);
	}
	response();
}

static void impl_Server_setSuperuserPassword(std::string pw, std::function< void() > response,
											 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;
	ServerDB::setSUPW(server_id, u8(pw));
	response();
}

#define ACCESS_Server_getLog_READ
static void impl_Server_getLog(int min, int max, std::function< void(const LogList &returnValue) > response,
							   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;

	::MumbleServer::LogList ll;

	QList< ServerDB::LogRecord > dblog = ServerDB::getLog(server_id, min, max);
	foreach (const ServerDB::LogRecord &e, dblog) {
		::MumbleServer::LogEntry le;
		logToLog(e, le);
		ll.push_back(le);
	}
	response(ll);
}

#define ACCESS_Server_getLogLen_READ
static void impl_Server_getLogLen(std::function< void(int returnValue) > response,
								  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER_EXISTS;

	int len = ServerDB::getLogLen(server_id);
	response(len);
}

#define ACCESS_Server_getUsers_READ
static void impl_Server_getUsers(std::function< void(const UserMap &returnValue) > response,
								 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	::MumbleServer::UserMap pm;
	foreach (const ::User *p, server->qhUsers) {
		::MumbleServer::User mp;
		if (static_cast< const ServerUser * >(p)->sState == ::ServerUser::Authenticated) {
			userToUser(p, mp);
			pm[p->uiSession] = mp;
		}
	}
	response(pm);
}

#define ACCESS_Server_getChannels_READ
static void impl_Server_getChannels(std::function< void(const ChannelMap &returnValue) > response,
									std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	::MumbleServer::ChannelMap cm;
	foreach (const ::Channel *c, server->qhChannels) {
		::MumbleServer::Channel mc;
		channelToChannel(c, mc);
		cm[c->iId] = mc;
	}
	response(cm);
}

static bool userSort(const ::User *a, const ::User *b) {
	return ::User::lessThan(a, b);
}

static bool channelSort(const ::Channel *a, const ::Channel *b) {
	return ::Channel::lessThan(a, b);
}

TreePtr recurseTree(const ::Channel *c) {
	TreePtr t = std::make_shared<Tree>();
	channelToChannel(c, t->c);
	QList<::User * > users = c->qlUsers;
	std::sort(users.begin(), users.end(), userSort);

	foreach (const ::User *p, users) {
		::MumbleServer::User mp;
		userToUser(p, mp);
		t->users.push_back(mp);
	}

	QList<::Channel * > channels = c->qlChannels;
	std::sort(channels.begin(), channels.end(), channelSort);

	foreach (const ::Channel *chn, channels) { t->children.push_back(recurseTree(chn)); }

	return t;
}

#define ACCESS_Server_getTree_READ
static void impl_Server_getTree(std::function< void(const std::shared_ptr< Tree > &returnValue) > response,
								std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	response(recurseTree(server->qhChannels.value(0)));
}

#define ACCESS_Server_getCertificateList_READ
static void impl_Server_getCertificateList(int session,
										   std::function< void(const CertificateList &returnValue) > response,
										   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	::MumbleServer::CertificateList certs;

	const QList< QSslCertificate > &certlist = user->peerCertificateChain();

	certs.resize(certlist.size());
	for (int i = 0; i < certlist.size(); ++i) {
		::MumbleServer::CertificateDer der;
		QByteArray qba = certlist.at(i).toDer();
		der.resize(qba.size());
		const char *ptr = qba.constData();
		for (int j = 0; j < qba.size(); ++j)
			der[j] = ptr[j];
		certs[i] = der;
	}
	response(certs);
}

#define ACCESS_Server_getBans_READ
static void impl_Server_getBans(std::function< void(const BanList &returnValue) > response,
								std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	::MumbleServer::BanList bl;
	foreach (const ::Ban &ban, server->qlBans) {
		::MumbleServer::Ban mb;
		banToBan(ban, mb);
		bl.push_back(mb);
	}
	response(bl);
}

static void impl_Server_setBans(BanList bans, std::function< void() > response,
								std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	{
		QWriteLocker wl(&server->qrwlVoiceThread);
		server->qlBans.clear();
		foreach (const ::MumbleServer::Ban &mb, bans) {
			::Ban ban;
			banToBan(mb, ban);
			server->qlBans << ban;
		}
	}

	server->saveBans();

	response();
}

static void impl_Server_kickUser(int session, std::string reason, std::function< void() > response,
								 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	MumbleProto::UserRemove mpur;
	mpur.set_session(session);
	mpur.set_reason(reason);
	server->sendAll(mpur);
	user->disconnectSocket();
	response();
}

static void impl_Server_sendMessage(int session, std::string text, std::function< void() > response,
									std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	server->sendTextMessage(nullptr, user, false, u8(text));
	response();
}

#define ACCESS_Server_hasPermission_READ
static void impl_Server_hasPermission(int session, int channelid, int perm,
									  std::function< void(bool returnValue) > response,
									  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;
	NEED_CHANNEL;
	response(server->hasPermission(user, channel, static_cast< ChanACL::Perm >(perm)));
}

#define ACCESS_Server_effectivePermissions_READ
static void impl_Server_effectivePermissions(int session, int channelid,
											 std::function< void(int returnValue) > response,
											 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;
	NEED_CHANNEL;
	response(server->effectivePermissions(user, channel));
}

static void impl_Server_addContextCallback(int session, std::string action, std::string text,
										   ServerContextCallbackPrxPtr cbptr, int ctx,
										   std::function< void() > response,
										   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	const QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > &qmPrx =
		mi->getServerContextCallbacks(server)[session];

	if (!(ctx
		  & (MumbleProto::ContextActionModify_Context_Server | MumbleProto::ContextActionModify_Context_Channel
			 | MumbleProto::ContextActionModify_Context_User))) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
		return;
	}

	try {
		const MumbleServer::ServerContextCallbackPrxPtr &oneway =
			Ice::checkedCast< MumbleServer::ServerContextCallbackPrx >(
			cbptr->ice_oneway()->ice_connectionCached(false)->ice_timeout(5000));
		if (qmPrx.contains(u8(action))) {
			// Since the server has no notion of the ctx part of the context action
			// make sure we remove them all clientside when overriding an old callback
			MumbleProto::ContextActionModify mpcam;
			mpcam.set_action(action);
			mpcam.set_operation(MumbleProto::ContextActionModify_Operation_Remove);
			server->sendMessage(user, mpcam);
		}
		mi->addServerContextCallback(server, session, u8(action), oneway);
		response();
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
		return;
	}

	MumbleProto::ContextActionModify mpcam;
	mpcam.set_action(action);
	mpcam.set_text(text);
	mpcam.set_context(ctx);
	mpcam.set_operation(MumbleProto::ContextActionModify_Operation_Add);
	server->sendMessage(user, mpcam);
}

static void impl_Server_removeContextCallback(std::shared_ptr< ServerContextCallbackPrx > cbptr,
											  std::function< void() > response,
											  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	const QMap< int, QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > > &qmPrx =
		mi->getServerContextCallbacks(server);

	try {
		const MumbleServer::ServerContextCallbackPrxPtr &oneway =
			Ice::uncheckedCast < MumbleServer::ServerContextCallbackPrx>(
			cbptr->ice_oneway()->ice_connectionCached(false)->ice_timeout(5000));

		foreach (int session, qmPrx.keys()) {
			ServerUser *user                                                    = server->qhUsers.value(session);
			const QMap< QString, ::MumbleServer::ServerContextCallbackPrxPtr > &qm = qmPrx[session];
			foreach (const QString &act, qm.keys(oneway)) {
				mi->removeServerContextCallback(server, session, act);

				// Ask clients to remove the clientside callbacks
				if (user) {
					MumbleProto::ContextActionModify mpcam;
					mpcam.set_action(iceString(act));
					mpcam.set_operation(MumbleProto::ContextActionModify_Operation_Remove);
					server->sendMessage(user, mpcam);
				}
			}
		}

		response();
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
	}
}

#define ACCESS_Server_getState_READ
static void impl_Server_getState(int session, std::function< void(const MumbleServer::User &returnValue) > response,
								 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	::MumbleServer::User mp;
	userToUser(user, mp);
	response(mp);
}

static void impl_Server_setState(MumbleServer::User state, std::function< void() > response,
								 std::function< void(std::exception_ptr) > exception, int server_id) {
	int session = state.session;
	::Channel *channel;
	NEED_SERVER;
	NEED_PLAYER;
	NEED_CHANNEL_VAR(channel, state.channel);

	server->setUserState(user, channel, state.mute, state.deaf, state.suppress, state.prioritySpeaker, u8(state.name),
						 u8(state.comment));
	response();
}

static void impl_Server_sendMessageChannel(int channelid, bool tree, std::string text, std::function< void() > response,
										   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;

	server->sendTextMessage(channel, nullptr, tree, u8(text));
	response();
}

#define ACCESS_Server_getChannelState_READ
static void impl_Server_getChannelState(int channelid, std::function< void(const MumbleServer::Channel &returnValue) > response,
										std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;

	::MumbleServer::Channel mc;
	channelToChannel(channel, mc);
	response(mc);
}

static void impl_Server_setChannelState(MumbleServer::Channel state, std::function< void() > response,
										std::function< void(std::exception_ptr) > exception, int server_id) {
	int channelid = state.id;
	NEED_SERVER;
	NEED_CHANNEL;
	::Channel *np = nullptr;
	if (channel->iId != 0) {
		NEED_CHANNEL_VAR(np, state.parent);
	}

	QString qsName = u8(state.name);

	QSet<::Channel * > newset;
	foreach (int linkid, state.links) {
		::Channel *cLink;
		NEED_CHANNEL_VAR(cLink, linkid);
		newset << cLink;
	}

	if (!server->canNest(np, channel)) {
		exception(std::make_exception_ptr(::MumbleServer::NestingLimitException()));
		return;
	}

	if (!server->setChannelState(channel, np, qsName, newset, u8(state.description), state.position))
		exception(std::make_exception_ptr(::MumbleServer::InvalidChannelException()));
	else
		response();
}

static void impl_Server_removeChannel(int channelid, std::function< void() > response,
									  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;

	if (!channel->cParent) {
		exception(std::make_exception_ptr(::MumbleServer::InvalidChannelException()));
	} else {
		server->removeChannel(channel);
		response();
	}
}

static void impl_Server_addChannel(std::string name, int parent, std::function< void(int returnValue) > response,
								   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	::Channel *p, *nc;
	NEED_CHANNEL_VAR(p, parent);

	if (!server->canNest(p)) {
		exception(std::make_exception_ptr(::MumbleServer::NestingLimitException()));
		return;
	}

	QString qsName = u8(name);

	nc = server->addChannel(p, qsName);
	server->updateChannel(nc);

	int newid = nc->iId;

	MumbleProto::ChannelState mpcs;
	mpcs.set_channel_id(newid);
	mpcs.set_parent(parent);
	mpcs.set_name(name);
	server->sendAll(mpcs);

	response(newid);
}

#define ACCESS_Server_getACL_READ
static void
	impl_Server_getACL(int channelid,
					   std::function< void(const ACLList &acls, const GroupList &groups, bool inherit) > response,
					   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;

	::MumbleServer::ACLList acls;
	::MumbleServer::GroupList groups;

	QStack<::Channel * > chans;
	::Channel *p;
	ChanACL *acl;
	p = channel;
	while (p) {
		chans.push(p);
		if ((p == channel) || (p->bInheritACL))
			p = p->cParent;
		else
			p = nullptr;
	}

	bool inherit = channel->bInheritACL;

	while (!chans.isEmpty()) {
		p = chans.pop();
		foreach (acl, p->qlACL) {
			if ((p == channel) || (acl->bApplySubs)) {
				::MumbleServer::ACL ma;
				ACLtoACL(acl, ma);
				if (p != channel)
					ma.inherited = true;
				acls.push_back(ma);
			}
		}
	}

	p                              = channel->cParent;
	const QSet< QString > allnames = ::Group::groupNames(channel);
	foreach (const QString &name, allnames) {
		::Group *g  = channel->qhGroups.value(name);
		::Group *pg = p ? ::Group::getGroup(p, name) : nullptr;
		if (!g && !pg)
			continue;
		::MumbleServer::Group mg;
		groupToGroup(g ? g : pg, mg);
		QSet< int > members;
		if (pg)
			members = pg->members();
		if (g) {
			QVector< int > addVec    = g->qsAdd.values().toVector();
			QVector< int > removeVec = g->qsRemove.values().toVector();

			mg.add       = std::vector< int >(addVec.begin(), addVec.end());
			mg.remove    = std::vector< int >(removeVec.begin(), removeVec.end());
			mg.inherited = false;
			members += g->qsAdd;
			members -= g->qsRemove;
		} else {
			mg.inherited = true;
		}

		QVector< int > memberVec = members.values().toVector();
		mg.members               = std::vector< int >(memberVec.begin(), memberVec.end());
		groups.push_back(mg);
	}
	response(acls, groups, inherit);
}

static void impl_Server_setACL(int channelid, ACLList acls, GroupList groups, bool inherit,
							   std::function< void() > response, std::function< void(std::exception_ptr) > exception,
							   int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;

	{
		QWriteLocker locker(&server->qrwlVoiceThread);

		::Group *g;
		ChanACL *acl;

		QHash< QString, QSet< int > > hOldTemp;
		foreach (g, channel->qhGroups) {
			hOldTemp.insert(g->qsName, g->qsTemporary);
			delete g;
		}
		foreach (acl, channel->qlACL)
			delete acl;

		channel->qhGroups.clear();
		channel->qlACL.clear();

		channel->bInheritACL = inherit;
		foreach (const ::MumbleServer::Group &gi, groups) {
			QString name    = u8(gi.name);
			g               = new ::Group(channel, name);
			g->bInherit     = gi.inherit;
			g->bInheritable = gi.inheritable;
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
			QVector< int > addVec(gi.add.begin(), gi.add.end());
			QVector< int > removeVec(gi.remove.begin(), gi.remove.end());

			g->qsAdd    = QSet< int >(addVec.begin(), addVec.end());
			g->qsRemove = QSet< int >(removeVec.begin(), removeVec.end());
#else
			// Qt 5.14 prefers to use the new range-based constructor for vectors and sets
			g->qsAdd    = QVector< int >::fromStdVector(gi.add).toList().toSet();
			g->qsRemove = QVector< int >::fromStdVector(gi.remove).toList().toSet();
#endif
			g->qsTemporary = hOldTemp.value(name);
		}
		foreach (const ::MumbleServer::ACL &ai, acls) {
			acl             = new ChanACL(channel);
			acl->bApplyHere = ai.applyHere;
			acl->bApplySubs = ai.applySubs;
			acl->iUserId    = ai.userid;
			acl->qsGroup    = u8(ai.group);
			acl->pDeny      = static_cast< ChanACL::Permissions >(ai.deny) & ChanACL::All;
			acl->pAllow     = static_cast< ChanACL::Permissions >(ai.allow) & ChanACL::All;
		}
	}

	server->clearACLCache();
	server->updateChannel(channel);
	response();
}

#define ACCESS_Server_getUserNames_READ
static void impl_Server_getUserNames(IdList ids, std::function< void(const NameMap &returnValue) > response,
									 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	::MumbleServer::NameMap nm;
	foreach (int userid, ids) { nm[userid] = iceString(server->getUserName(userid)); }
	response(nm);
}

#define ACCESS_Server_getUserIds_READ
static void impl_Server_getUserIds(NameList names, std::function< void(const IdMap &returnValue) > response,
								   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	::MumbleServer::IdMap im;
	foreach (const string &n, names) {
		QString name = u8(n);
		im[n]        = server->getUserID(name);
	}
	response(im);
}

static void impl_Server_registerUser(UserInfoMap im, std::function< void(int returnValue) > response,
									 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	QMap< int, QString > info;
	infoToInfo(im, info);

	int userid = server->registerUser(info);

	if (userid < 0)
		exception(std::make_exception_ptr(InvalidUserException()));
	else
		response(userid);
}

static void impl_Server_unregisterUser(int userid, std::function< void() > response,
									   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	bool success = server->unregisterUser(userid);

	if (!success) {
		exception(std::make_exception_ptr(InvalidUserException()));
	} else {
		response();
	}
}

static void impl_Server_updateRegistration(int id, UserInfoMap im, std::function< void() > response,
										   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	if (!server->isUserId(id)) {
		exception(std::make_exception_ptr(InvalidUserException()));
		return;
	}

	QMap< int, QString > info;
	infoToInfo(im, info);

	if (!server->setInfo(id, info)) {
		exception(std::make_exception_ptr(InvalidUserException()));
		return;
	}

	if (info.contains(ServerDB::User_Comment)) {
		foreach (ServerUser *u, server->qhUsers) {
			if (u->iId == id)
				server->setUserState(u, u->cChannel, u->bMute, u->bDeaf, u->bSuppress, u->bPrioritySpeaker, u->qsName,
									 info.value(ServerDB::User_Comment));
		}
	}

	response();
}

#define ACCESS_Server_getRegistration_READ
static void impl_Server_getRegistration(int userid, std::function< void(const UserInfoMap &returnValue) > response,
										std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	QMap< int, QString > info = server->getRegistration(userid);

	if (info.isEmpty()) {
		exception(std::make_exception_ptr(InvalidUserException()));
		return;
	}

	MumbleServer::UserInfoMap im;
	infoToInfo(info, im);
	response(im);
}

#define ACCESS_Server_getRegisteredUsers_READ
static void impl_Server_getRegisteredUsers(std::string filter,
										   std::function< void(const NameMap &returnValue) > response,
										   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	MumbleServer::NameMap rpl;

	const QMap< int, QString > l = server->getRegisteredUsers(u8(filter));
	QMap< int, QString >::const_iterator i;
	for (i = l.constBegin(); i != l.constEnd(); ++i) {
		rpl[i.key()] = u8(i.value());
	}

	response(rpl);
}

#define ACCESS_Server_verifyPassword_READ
static void impl_Server_verifyPassword(std::string name, std::string pw,
									   std::function< void(int returnValue) > response,
									   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	QString uname = u8(name);
	response(server->authenticate(uname, u8(pw)));
}

#define ACCESS_Server_getTexture_READ
static void impl_Server_getTexture(int userid, std::function< void(const Texture &returnValue) > response,
								   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	if (!server->isUserId(userid)) {
		exception(std::make_exception_ptr(InvalidUserException()));
		return;
	}

	const QByteArray &qba = server->getUserTexture(userid);

	::MumbleServer::Texture tex;
	tex.resize(qba.size());
	const char *ptr = qba.constData();
	for (int i = 0; i < qba.size(); ++i)
		tex[i] = ptr[i];

	response(tex);
}

static void impl_Server_setTexture(int userid, Texture tex, std::function< void() > response,
								   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	if (!server->isUserId(userid)) {
		exception(std::make_exception_ptr(InvalidUserException()));
		return;
	}

	QByteArray qba(static_cast< int >(tex.size()), 0);
	char *ptr = qba.data();
	for (unsigned int i = 0; i < tex.size(); ++i)
		ptr[i] = tex[i];

	if (!server->setTexture(userid, qba)) {
		exception(std::make_exception_ptr(InvalidTextureException()));
	} else {
		ServerUser *user = server->qhUsers.value(userid);
		if (user) {
			MumbleProto::UserState mpus;
			mpus.set_session(user->uiSession);
			mpus.set_texture(blob(user->qbaTexture));

			server->sendAll(mpus, Version::fromComponents(1, 2, 2), Version::CompareMode::LessThan);
			if (!user->qbaTextureHash.isEmpty()) {
				mpus.clear_texture();
				mpus.set_texture_hash(blob(user->qbaTextureHash));
			}
			server->sendAll(mpus, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);
		}

		response();
	}
}

#define ACCESS_Server_getUptime_READ
static void impl_Server_getUptime(std::function< void(int returnValue) > response,
								  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	response(static_cast< int >(server->tUptime.elapsed() / 1000000LL));
}

static void impl_Server_updateCertificate(std::string certificate, std::string privateKey, std::string passphrase,
										  std::function< void() > response,
										  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	QByteArray certPem(certificate.c_str());
	QByteArray privateKeyPem(privateKey.c_str());
	QByteArray passphraseBytes(passphrase.c_str());

	// Verify that we can load the certificate.
	QSslCertificate cert(certPem);
	if (cert.isNull()) {
		ERR_clear_error();
		exception(std::make_exception_ptr(InvalidInputDataException()));
		return;
	}

	// Verify that we can load the private key.
	QSslKey privKey = ::Server::privateKeyFromPEM(privateKeyPem, passphraseBytes);
	if (privKey.isNull()) {
		ERR_clear_error();
		exception(std::make_exception_ptr(InvalidInputDataException()));
		return;
	}

	// Ensure that the private key is usable with the given
	// certificate.
	if (!::Server::isKeyForCert(privKey, cert)) {
		ERR_clear_error();
		exception(std::make_exception_ptr(InvalidInputDataException()));
		return;
	}

	// All our sanity checks passed.
	// The certificate and private key are usable, so
	// update the server to use them.
	server->setConf("certificate", u8(certificate));
	server->setConf("key", u8(privateKey));
	server->setConf("passphrase", u8(passphrase));
	{
		QWriteLocker wl(&server->qrwlVoiceThread);
		server->initializeCert();
	}

	response();
}

static void impl_Server_startListening(int session, int channelid, std::function< void() > response,
									   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;
	NEED_PLAYER;

	server->startListeningToChannel(user, channel);

	response();
}

static void impl_Server_stopListening(int session, int channelid, std::function< void() > response,
									  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;
	NEED_PLAYER;

	server->stopListeningToChannel(user, channel);

	response();
}

static void impl_Server_isListening(int session, int channelid, std::function< void(bool returnValue) > response,
									std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;
	NEED_PLAYER;

	response(server->m_channelListenerManager.isListening(user->uiSession, channel->iId));
}

static void impl_Server_getListeningChannels(int session, std::function< void(const IntList &returnValue) > response,
											 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	::MumbleServer::IntList channelIDs;
	foreach (int currentChannelID, server->m_channelListenerManager.getListenedChannelsForUser(user->uiSession)) {
		channelIDs.push_back(currentChannelID);
	}

	response(channelIDs);
}

static void impl_Server_getListeningUsers(int channelid, std::function< void(const IntList &returnValue) > response,
										  std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;

	::MumbleServer::IntList userSessions;
	foreach (unsigned int currentSession, server->m_channelListenerManager.getListenersForChannel(channel->iId)) {
		userSessions.push_back(currentSession);
	}

	response(userSessions);
}

static void impl_Server_sendWelcomeMessage(IdList receiverUserIDs, std::function< void() > response,
										   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;

	for (unsigned int session : receiverUserIDs) {
		NEED_PLAYER;

		server->sendWelcomeMessageTo(user);
	}

	response();
}

static void impl_Server_getListenerVolumeAdjustment(int channelid, int session,
													std::function< void(float returnValue) > response,
													std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;
	NEED_PLAYER;

	response(
		server->m_channelListenerManager.getListenerVolumeAdjustment(user->uiSession, channel->iId).factor);
}

static void impl_Server_setListenerVolumeAdjustment(int channelid, int session, float volumeAdjustment,
													std::function< void() > response,
													std::function< void(std::exception_ptr) > exception,
													int server_id) {
	NEED_SERVER;
	NEED_CHANNEL;
	NEED_PLAYER;

	server->setListenerVolumeAdjustment(user, channel, VolumeAdjustment::fromFactor(volumeAdjustment));

	response();
}

static void impl_Server_addUserToGroup(int channelid, int session, std::string group, std::function< void() > response,
									   std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;
	NEED_CHANNEL;

	QString qsgroup = u8(group);
	if (qsgroup.isEmpty()) {
		exception(std::make_exception_ptr(InvalidChannelException()));
		return;
	}

	{
		QWriteLocker wl(&server->qrwlVoiceThread);

		::Group *g = channel->qhGroups.value(qsgroup);
		if (!g)
			g = new ::Group(channel, qsgroup);

		g->qsTemporary.insert(-session);
	}

	server->clearACLCache(user);

	response();
}

static void impl_Server_removeUserFromGroup(int channelid, int session, std::string group,
											std::function< void() > response,
											std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;
	NEED_CHANNEL;

	QString qsgroup = u8(group);
	if (qsgroup.isEmpty()) {
		exception(std::make_exception_ptr(InvalidChannelException()));
		return;
	}

	{
		QWriteLocker qrwl(&server->qrwlVoiceThread);

		::Group *g = channel->qhGroups.value(qsgroup);
		if (!g)
			g = new ::Group(channel, qsgroup);

		g->qsTemporary.remove(-session);
	}

	server->clearACLCache(user);

	response();
}

static void impl_Server_redirectWhisperGroup(int session, std::string source, std::string target,
											 std::function< void() > response,
											 std::function< void(std::exception_ptr) > exception, int server_id) {
	NEED_SERVER;
	NEED_PLAYER;

	QString qssource = u8(source);
	QString qstarget = u8(target);

	{
		QWriteLocker wl(&server->qrwlVoiceThread);

		if (qstarget.isEmpty())
			user->qmWhisperRedirect.remove(qssource);
		else
			user->qmWhisperRedirect.insert(qssource, qstarget);
	}

	server->clearACLCache(user);

	response();
}

#define ACCESS_Meta_getSliceChecksums_ALL
static void
	impl_Meta_getSliceChecksums(std::function< void(const Ice::SliceChecksumDict &returnValue) > response,
								std::function< void(std::exception_ptr) >, const Ice::ObjectAdapterPtr) {
	response(::Ice::sliceChecksums());
}

#define ACCESS_Meta_getServer_READ
static void impl_Meta_getServer(int id, std::function< void(const std::shared_ptr< ServerPrx > &returnValue) > response,
								std::function< void(std::exception_ptr) >,
								const Ice::ObjectAdapterPtr adapter) {
	QList< int > server_list = ServerDB::getAllServers();
	if (!server_list.contains(id))
		response(nullptr);
	else
		response(idToProxy(id, adapter));
}

static void impl_Meta_newServer(std::function< void(const std::shared_ptr< ServerPrx > &returnValue) > response,
								std::function< void(std::exception_ptr) >,
								const Ice::ObjectAdapterPtr adapter) {
	response(idToProxy(ServerDB::addServer(), adapter));
}

#define ACCESS_Meta_getAllServers_READ
static void
	impl_Meta_getAllServers(std::function< void(const ServerList &returnValue) > response,
							std::function< void(std::exception_ptr) >,
							const Ice::ObjectAdapterPtr adapter) {
	::MumbleServer::ServerList sl;

	foreach (int id, ServerDB::getAllServers())
		sl.push_back(idToProxy(id, adapter));
	response(sl);
}

#define ACCESS_Meta_getDefaultConf_READ
static void impl_Meta_getDefaultConf(std::function< void(const ::MumbleServer::ConfigMap &returnValue) > response,
									 std::function< void(std::exception_ptr) >,
									 const Ice::ObjectAdapterPtr) {
	::MumbleServer::ConfigMap cm;
	QMap< QString, QString >::const_iterator i;
	for (i = meta->mp.qmConfig.constBegin(); i != meta->mp.qmConfig.constEnd(); ++i) {
		if (i.key() == "key" || i.key() == "passphrase")
			continue;
		cm[iceString(i.key())] = iceString(i.value());
	}
	response(cm);
}

#define ACCESS_Meta_getBootedServers_READ
static void
	impl_Meta_getBootedServers(std::function< void(const ServerList &returnValue) > response,
							   std::function< void(std::exception_ptr) >,
							   const Ice::ObjectAdapterPtr adapter) {
	::MumbleServer::ServerList sl;

	foreach (int id, meta->qhServers.keys())
		sl.push_back(idToProxy(id, adapter));
	response(sl);
}

#define ACCESS_Meta_getVersion_ALL
static void
	impl_Meta_getVersion(std::function< void(int major, int minor, int patch, const std::string &text) > response,
						 std::function< void(std::exception_ptr) >,
						 const Ice::ObjectAdapterPtr) {
	Version::component_t major, minor, patch;
	QString txt;
	::Meta::getVersion(major, minor, patch, txt);
	response(major, minor, patch, iceString(txt));
}

static void impl_Meta_addCallback(MumbleServer::MetaCallbackPrxPtr cbptr, std::function< void() > response,
								  std::function< void(std::exception_ptr) > exception, const Ice::ObjectAdapterPtr) {
	try {
		const MumbleServer::MetaCallbackPrxPtr oneway = Ice::checkedCast<MumbleServer::MetaCallbackPrx>(
			cbptr->ice_oneway()->ice_connectionCached(false)->ice_timeout(5000));
		mi->addMetaCallback(oneway);
		response();
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
	}
}

static void impl_Meta_removeCallback(std::shared_ptr< MetaCallbackPrx > cbptr, std::function< void() > response,
									 std::function< void(std::exception_ptr) > exception, const Ice::ObjectAdapterPtr) {
	try {
		const MumbleServer::MetaCallbackPrxPtr &oneway =
			Ice::uncheckedCast< MumbleServer::MetaCallbackPrx>(
			cbptr->ice_oneway()->ice_connectionCached(false)->ice_timeout(5000));
		mi->removeMetaCallback(oneway);
		response();
	} catch (...) {
		exception(std::make_exception_ptr(InvalidCallbackException()));
	}
}

#define ACCESS_Meta_getUptime_ALL
static void impl_Meta_getUptime(std::function< void(int returnValue) > response,
								std::function< void(std::exception_ptr) >,
								const Ice::ObjectAdapterPtr) {
	response(static_cast< int >(meta->tUptime.elapsed() / 1000000LL));
}

#include "MumbleServerIceWrapper.cpp"

#undef FIND_SERVER
#undef NEED_SERVER_EXISTS
#undef NEED_SERVER
#undef NEED_PLAYER
#undef NEED_CHANNEL_VAR
#undef NEED_CHANNEL
#undef ACCESS_Server_isRunning_READ
#undef ACCESS_Server_id_READ
#undef ACCESS_Server_getConf_READ
#undef ACCESS_Server_getAllConf_READ
#undef ACCESS_Server_getLog_READ
#undef ACCESS_Server_getLogLen_READ
#undef ACCESS_Server_getUsers_READ
#undef ACCESS_Server_getChannels_READ
#undef ACCESS_Server_getTree_READ
#undef ACCESS_Server_getCertificateList_READ
#undef ACCESS_Server_getBans_READ
#undef ACCESS_Server_hasPermission_READ
#undef ACCESS_Server_effectivePermissions_READ
#undef ACCESS_Server_getState_READ
#undef ACCESS_Server_getChannelState_READ
#undef ACCESS_Server_getACL_READ
#undef ACCESS_Server_getUserNames_READ
#undef ACCESS_Server_getUserIds_READ
#undef ACCESS_Server_getRegistration_READ
#undef ACCESS_Server_getRegisteredUsers_READ
#undef ACCESS_Server_verifyPassword_READ
#undef ACCESS_Server_getTexture_READ
#undef ACCESS_Server_getUptime_READ
#undef ACCESS_Meta_getSliceChecksums_ALL
#undef ACCESS_Meta_getServer_READ
#undef ACCESS_Meta_getAllServers_READ
#undef ACCESS_Meta_getDefaultConf_READ
#undef ACCESS_Meta_getBootedServers_READ
#undef ACCESS_Meta_getVersion_ALL
#undef ACCESS_Meta_getUptime_ALL
