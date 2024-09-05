'use strict';

const groupsAPI = {};
// const groups = require('./groups'); // Removed the self-import


const groups = require('../groups');
const user = require('../user');
const { logGroupEvent } = require('../utils'); // Adjust path as needed

// const logGroupEvent = require('../logGroupEvent.js');




async function checkPrivileges(caller, uid, owner, invited) {
	if (!owner && caller.uid !== parseInt(uid, 10)) {
		throw new Error('[[error:not-allowed]]');
	}
	if (!invited) {
		throw new Error('[[error:not-invited]]');
	}
}

async function validateInputData(uid) {
	const parsedUid = parseInt(uid, 10);
	if (isNaN(parsedUid)) {
		throw new Error('[[error:invalid-uid]]');
	}
	return parsedUid;
}

async function getGroupData(groupName) {
	const group = await groups.getGroupData(groupName);
	if (!group) {
		throw new Error('[[error:group-not-found]]');
	}
	return group;
}

groupsAPI.join = async function (caller, uid, groupName) {
	const owner = await groups.isOwner(caller.uid, groupName, false);
	const invited = await groups.isInvitedToGroup(uid, groupName);

	await checkPrivileges(caller, uid, owner, invited);

	const parsedUid = await validateInputData(uid);
	await getGroupData(groupName); // Removed unused 'group' variable

	await groups.rejectMembership(groupName, parsedUid);
	if (!owner) {
		logGroupEvent(caller, 'group-invite-reject', { groupName });
	}
};

groupsAPI.leave = async function (caller, data) {
	if (!data) {
		throw new Error('[[error:invalid-data]]');
	}
	if (caller.uid <= 0) {
		throw new Error('[[error:invalid-uid]]');
	}
	const isSelf = parseInt(caller.uid, 10) === parseInt(data.uid, 10);
	const groupName = await groups.getGroupNameByGroupSlug(data.slug);
	if (!groupName) {
		throw new Error('[[error:no-group]]');
	}

	if (typeof groupName !== 'string') {
		throw new Error('[[error:invalid-group-name]]');
	}

	if (groupName === 'administrators' && isSelf) {
		throw new Error('[[error:cant-remove-self-as-admin]]');
	}

	const [isCallerOwner, userExists, isMember] = await Promise.all([
		groups.isOwner(caller.uid, groupName),
		user.exists(data.uid),
		groups.isMember(data.uid, groupName),
	]);

	if (!userExists) {
		throw new Error('[[error:no-user]]');
	}
	if (!isMember) {
		throw new Error('[[error:not-member]]');
	}
	if (isCallerOwner && !isSelf) {
		throw new Error('[[error:cant-remove-other-owner]]');
	}

	await groups.leave(groupName, data.uid);
	logGroupEvent(caller, 'group-leave', { groupName, uid: data.uid });
};

module.exports = groupsAPI;
