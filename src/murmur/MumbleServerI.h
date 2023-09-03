// Copyright 2022-2023 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_MURMURI_H_
#define MUMBLE_MURMUR_MURMURI_H_

#include <MumbleServer.h>

namespace MumbleServer {

class ServerI : virtual public Server {
public:
	virtual void isRunningAsync(std::function< void(bool returnValue) > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void startAsync(std::function< void() > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void stopAsync(std::function< void() > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void deleteAsync(std::function< void() > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void addCallbackAsync(std::shared_ptr< ServerCallbackPrx > cb, std::function< void() > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void removeCallbackAsync(std::shared_ptr< ServerCallbackPrx > cb, std::function< void() > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void setAuthenticatorAsync(std::shared_ptr< ServerAuthenticatorPrx > auth, std::function< void() > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void idAsync(std::function< void(int returnValue) > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getConfAsync(std::string key, std::function< void(const std::string &returnValue) > response, std::function< void(std::exception_ptr) > exception, const Ice::Current &);

	virtual void getAllConfAsync(std::function< void(const ConfigMap &returnValue) > response,
								 std::function< void(std::exception_ptr) > exception, const Ice::Current &current); 

	virtual void setConfAsync(std::string key, std::string value, std::function< void() > response,
							  std::function< void(std::exception_ptr) > exception, const Ice::Current &current); 

	virtual void setSuperuserPasswordAsync(std::string pw, std::function< void() > response,
											   std::function< void(std::exception_ptr) > exception,
											   const Ice::Current &current);

	virtual void getLogAsync(int first, int last, std::function< void(const LogList &returnValue) > response,
							 std::function< void(std::exception_ptr) > exception, const Ice::Current &current); 

	virtual void getLogLenAsync(std::function< void(int returnValue) > response,
								std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getUsersAsync(std::function< void(const UserMap &returnValue) > response,
							   std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getChannelsAsync(std::function< void(const ChannelMap &returnValue) > response,
								  std::function< void(std::exception_ptr) > exception, const Ice::Current &current); 

	virtual void getTreeAsync(std::function< void(const std::shared_ptr< Tree > &returnValue) > response,
							  std::function< void(std::exception_ptr) > exception, const Ice::Current &current); 

	virtual void getCertificateListAsync(int session,
										 std::function< void(const CertificateList &returnValue) > response,
										 std::function< void(std::exception_ptr) > exception,
										 const Ice::Current &current);

	virtual void getBansAsync(std::function< void(const BanList &returnValue) > response,
							  std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void setBansAsync(BanList bans, std::function< void() > response,
							  std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void kickUserAsync(int session, std::string reason, std::function< void() > response,
							   std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void sendMessageAsync(int session, std::string text, std::function< void() > response,
								  std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void hasPermissionAsync(int session, int channelid, int perm,
									std::function< void(bool returnValue) > response,
									std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void effectivePermissionsAsync(int session, int channelid, std::function< void(int returnValue) > response,
										   std::function< void(std::exception_ptr) > exception,
										   const Ice::Current &current);

	virtual void addContextCallbackAsync(int session, std::string action, std::string text,
										 std::shared_ptr< ServerContextCallbackPrx > cb, int ctx,
										 std::function< void() > response,
										 std::function< void(std::exception_ptr) > exception,
										 const Ice::Current &current);

	virtual void removeContextCallbackAsync(std::shared_ptr< ServerContextCallbackPrx > cb,
											std::function< void() > response,
											std::function< void(std::exception_ptr) > exception,
											const Ice::Current &current);

	virtual void getStateAsync(int session, std::function< void(const User &returnValue) > response,
							   std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void setStateAsync(User state, std::function< void() > response,
							   std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getChannelStateAsync(int channelid, std::function< void(const Channel &returnValue) > response,
									  std::function< void(std::exception_ptr) > exception,
									  const Ice::Current &current);

	virtual void setChannelStateAsync(Channel state, std::function< void() > response,
									  std::function< void(std::exception_ptr) > exception,
									  const Ice::Current &current);

	virtual void removeChannelAsync(int channelid, std::function< void() > response,
									std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void addChannelAsync(std::string name, int parent, std::function< void(int returnValue) > response,
								 std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void sendMessageChannelAsync(int channelid, bool tree, std::string text, std::function< void() > response,
										 std::function< void(std::exception_ptr) > exception,
										 const Ice::Current &current);

	virtual void getACLAsync(int channelid,
							 std::function< void(const ACLList &acls, const GroupList &groups, bool inherit) > response,
							 std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void setACLAsync(int channelid, ACLList acls, GroupList groups, bool inherit,
							 std::function< void() > response, std::function< void(std::exception_ptr) > exception,
							 const Ice::Current &current);

	virtual void removeUserFromGroupAsync(int channelid, int session, std::string group,
										  std::function< void() > response,
										  std::function< void(std::exception_ptr) > exception,
										  const Ice::Current &current);

	virtual void addUserToGroupAsync(int channelid, int session, std::string group, std::function< void() > response,
									 std::function< void(std::exception_ptr) > exception,
									 const Ice::Current &current);

	virtual void redirectWhisperGroupAsync(int session, std::string source, std::string target,
										   std::function< void() > response,
										   std::function< void(std::exception_ptr) > exception,
										   const Ice::Current &current);

	virtual void getUserNamesAsync(IdList ids, std::function< void(const NameMap &returnValue) > response,
								   std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getUserIdsAsync(NameList names, std::function< void(const IdMap &returnValue) > response,
								 std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void registerUserAsync(UserInfoMap info, std::function< void(int returnValue) > response,
								   std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void unregisterUserAsync(int userid, std::function< void() > response,
									 std::function< void(std::exception_ptr) > exception,
									 const Ice::Current &current);

	virtual void updateRegistrationAsync(int userid, UserInfoMap info, std::function< void() > response,
										 std::function< void(std::exception_ptr) > exception,
										 const Ice::Current &current);

	virtual void getRegistrationAsync(int userid, std::function< void(const UserInfoMap &returnValue) > response,
									  std::function< void(std::exception_ptr) > exception,
									  const Ice::Current &current);

	virtual void getRegisteredUsersAsync(std::string filter, std::function< void(const NameMap &returnValue) > response,
										 std::function< void(std::exception_ptr) > exception,
										 const Ice::Current &current);

	virtual void verifyPasswordAsync(std::string name, std::string pw, std::function< void(int returnValue) > response,
									 std::function< void(std::exception_ptr) > exception,
									 const Ice::Current &current);

	virtual void getTextureAsync(int userid, std::function< void(const Texture &returnValue) > response,
								 std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void setTextureAsync(int userid, Texture tex, std::function< void() > response,
								 std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getUptimeAsync(std::function< void(int returnValue) > response,
								std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void updateCertificateAsync(std::string certificate, std::string privateKey, std::string passphrase,
										std::function< void() > response,
										std::function< void(std::exception_ptr) > exception,
										const Ice::Current &current);

	virtual void startListeningAsync(int userid, int channelid, std::function< void() > response,
									 std::function< void(std::exception_ptr) > exception,
									 const Ice::Current &current);

	virtual void stopListeningAsync(int userid, int channelid, std::function< void() > response,
									std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void isListeningAsync(int userid, int channelid, std::function< void(bool returnValue) > response,
								  std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void getListeningChannelsAsync(int userid, std::function< void(const IntList &returnValue) > response,
										   std::function< void(std::exception_ptr) > exception,
										   const Ice::Current &current);

	virtual void getListeningUsersAsync(int channelid, std::function< void(const IntList &returnValue) > response,
										std::function< void(std::exception_ptr) > exception,
										const Ice::Current &current);

	virtual void getListenerVolumeAdjustmentAsync(int channelid, int userid,
												  std::function< void(float returnValue) > response,
												  std::function< void(std::exception_ptr) > exception,
												  const Ice::Current &current);

	virtual void setListenerVolumeAdjustmentAsync(int channelid, int userid, float volumeAdjustment,
												  std::function< void() > response,
												  std::function< void(std::exception_ptr) > exception,
												  const Ice::Current &current);

	virtual void sendWelcomeMessageAsync(IdList receiverUserIDs, std::function< void() > response,
										 std::function< void(std::exception_ptr) > exception,
										 const Ice::Current &current);

	virtual void ice_ping(const Ice::Current &) const;
};

class MetaI : virtual public Meta {
public:
	virtual void getSliceChecksumsAsync(std::function< void(const Ice::SliceChecksumDict &returnValue) > response,
										std::function< void(std::exception_ptr) > exception,
										const Ice::Current &current);

	virtual void getServerAsync(int id,
								std::function< void(const std::shared_ptr< ServerPrx > &returnValue) > response,
								std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void newServerAsync(std::function< void(const std::shared_ptr< ServerPrx > &returnValue) > response,
								std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

    virtual void getBootedServersAsync(std::function< void(const ServerList &returnValue) > response,
									   std::function< void(std::exception_ptr) > exception,
									   const Ice::Current &current);

	virtual void getAllServersAsync(std::function< void(const ServerList &returnValue) > response,
									std::function< void(std::exception_ptr) > exception,
									const Ice::Current &current);

	virtual void getDefaultConfAsync(std::function< void(const ConfigMap &returnValue) > response,
									 std::function< void(std::exception_ptr) > exception,
									 const Ice::Current &current);

	virtual void getVersionAsync(std::function< void(int major, int minor, int patch, const std::string &text) > response,
						std::function< void(std::exception_ptr) > exception, const Ice::Current &current);

	virtual void addCallbackAsync(std::shared_ptr< MetaCallbackPrx > cb, std::function< void() > response,
								  std::function< void(std::exception_ptr) > exception,
								  const Ice::Current &current);

	virtual void removeCallbackAsync(std::shared_ptr< MetaCallbackPrx > cb, std::function< void() > response,
									 std::function< void(std::exception_ptr) > exception,
									 const Ice::Current &current);

	virtual void getUptimeAsync(std::function< void(int returnValue) > response,
								std::function< void(std::exception_ptr) > exception,
								const Ice::Current &current);

	virtual void getSliceAsync(std::function< void(const std::string &returnValue) > response,
							   std::function< void(std::exception_ptr) > exception,
							   const Ice::Current &current);
};

} // namespace MumbleServer

#endif
