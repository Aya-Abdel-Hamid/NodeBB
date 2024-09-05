'use strict';

const validator = require('validator');

const privileges = require('../privileges');
const events = require('../events');
const groups = require('../groups');
const user = require('../user');
const meta = require('../meta');
const notifications = require('../notifications');
const slugify = require('../slugify');

const groupsAPI = module.exports;

groupsAPI.list = async (caller, data) => {
	const groupsPerPage = 10;
	const start = parseInt(data.after || 0, 10);
	const stop = start + groupsPerPage - 1;
	const groupData = await groups.getGroupsBySort(data.sort, start, stop);
	console.log('........Running Instance .........');
	return { groups: groupData, nextStart: stop + 1 };
};

groupsAPI.create = async function (caller, data) {
	if (!caller.uid) {
		console.log('........Running Instance .........');
		throw new Error('[[error:no-privileges]]');
	} else if (!data) {
		console.log('........Running Instance .........');
		throw new Error('[[error:invalid-data]]');
	} else if (typeof data.name !== 'string' || groups.isPrivilegeGroup(data.name)) {
		console.log('........Running Instance .........');
		throw new Error('[[error:invalid-group-name]]');
	}

	const canCreate = await privileges.global.can('group:create', caller.uid);
	if (!canCreate) {
		console.log('........Running Instance .........');
		throw new Error('[[error:no-privileges]]');
	}

	console.log('........Running Instance .........');
	data.ownerUid = caller.uid;
	data.system = false;
	const groupData = await groups.create(data);
	logGroupEvent(caller, 'group-create', {
		groupName: data.name,
	});

	console.log('........Running Instance .........');
	return groupData;
};

groupsAPI.update = async function (caller, data) {
	if (!data) {
		console.log('........Running Instance .........');
		throw new Error('[[error:invalid-data]]');
	}
	const groupName = await groups.getGroupNameByGroupSlug(data.slug);
	await isOwner(caller, groupName);

	delete data.slug;
	await groups.update(groupName, data);

	return await groups.getGroupData(data.name || groupName);
};

groupsAPI.delete = async function (caller, data) {
	const groupName = await groups.getGroupNameByGroupSlug(data.slug);
	await isOwner(caller, groupName);
	if (
		groups.systemGroups.includes(groupName) ||
		groups.ephemeralGroups.includes(groupName)
	) {
		throw new Error('[[error:not-allowed]]');
	}

	await groups.destroy(groupName);
	logGroupEvent(caller, 'group-delete', {
		groupName: groupName,
	});
};

groupsAPI.listMembers = async (caller, data) => {
	const groupName = await groups.getGroupNameByGroupSlug(data.slug);

	await canSearchMembers(caller.uid, groupName);
	if (!await privileges.global.can('search:users', caller.uid)) {
		throw new Error('[[error:no-privileges]]');
	}

	const { query } = data;
	const after = parseInt(data.after || 0, 10);
	let response;
	if (query && query.length) {
		response = await groups.searchMembers({
			uid: caller.uid,
			query,
			groupName,
		});
		response.nextStart = null;
	} else {
		response = {
			users: await groups.getOwnersAndMembers(groupName, caller.uid, after, after + 19),
			nextStart: after + 20,
			matchCount: null,
			timing: null,
		};
	}

	return response;
};

async function canSearchMembers(uid, groupName) {
	const [isHidden, isMember, hasAdminPrivilege, isGlobalMod, viewGroups] = await Promise.all([
		groups.isHidden(groupName),
		groups.isMember(uid, groupName),
		privileges.admin.can('admin:groups', uid),
		user.isGlobalModerator(uid),
		privileges.global.can('view:groups', uid),
	]);

	if (!viewGroups || (isHidden && !isMember && !hasAdminPrivilege && !isGlobalMod)) {
		throw new Error('[[error:no-privileges]]');
	}
}

groupsAPI.join = async function (caller, data) {
	if (!data || !data.uid) {
		throw new Error('[[error:invalid-data]]');
	}
	if (caller.uid <= 0) {
		throw new Error('[[error:invalid-uid]]');
	}

	const groupName = await groups.getGroupNameByGroupSlug(data.slug);
	if (!groupName) {
		throw new Error('[[error:no-group]]');
	}

	const [groupData, userExists, isCallerAdmin] = await Promise.all([
		groups.getGroupData(groupName),
		user.exists(data.uid),
		privileges.admin.can('admin:groups', caller.uid),
	]);

	if (!userExists) {
		throw new Error('[[error:invalid-uid]]');
	}

	const isSelf = parseInt(caller.uid, 10) === parseInt(data.uid, 10);
	if (!isCallerAdmin) {
		if (groups.systemGroups.includes(groupName) || groups.isPrivilegeGroup(groupName)) {
			throw new Error('[[error:not-allowed]]');
		}
		if (!isSelf && (groupData.private || groupData.disableJoinRequests)) {
			throw new Error('[[error:group-join-disabled]]');
		}
	}

	if (!meta.config.allowPrivateGroups && isSelf) {
		await handlePublicGroups(caller, groupName, data.uid);
		return;
	}

	if (isRestrictedJoin(isCallerAdmin, isSelf, groupData)) {
		throw new Error('[[error:group-join-disabled]]');
	}

	if (canJoinGroup(groupData, isSelf, isCallerAdmin)) {
		await groups.join(groupName, data.uid);
		logGroupEvent(caller, `group-${isSelf ? 'join' : 'add-member'}`, {
			groupName,
			targetUid: data.uid,
		});
	} else {
		throw new Error('[[error:not-allowed]]');
	}

	async function handlePublicGroups(caller, groupName, uid) {
		await groups.join(groupName, uid);
		logGroupEvent(caller, 'group-join', {
			groupName,
			targetUid: uid,
		});
	}

	function isRestrictedJoin(isCallerAdmin, isSelf, groupData) {
		return !isCallerAdmin && isSelf && groupData.private && groupData.disableJoinRequests;
	}

	function canJoinGroup(groupData, isSelf, isCallerAdmin) {
		return (!groupData.private && isSelf) || isCallerAdmin;
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

	const [groupData, isCallerOwner, userExists, isMember] = await Promise.all([
		groups.getGroupData(groupName),
		isOwner(caller, groupName, false),
		user.exists(data.uid),
		groups.isMember(data.uid, groupName),
	]);

	if (!isMember) {
		throw new Error('[[error:group-not-member]]');
	}

	if (!userExists) {
		throw new Error('[[error:invalid-uid]]');
	}

	if (groupData.disableLeave && isSelf) {
		throw new Error('[[error:group-leave-disabled]]');
	}

	if (isSelf || isCallerOwner) {
		await groups.leave(groupName, data.uid);
	} else {
		throw new Error('[[error:no-privileges]]');
	}

	const { displayname } = await user.getUserFields(data.uid, ['username']);

	const notification = await notifications.create({
		type: 'group-leave',
		bodyShort: `[[groups:membership.leave.notification-title, ${displayname}, ${groupName}]]`,
		nid: `group:${validator.escape(groupName)}:uid:${data.uid}:group-leave`,
		path: `/groups/${slugify(groupName)}`,
		from: data.uid,
	});
	const uids = await groups.getOwners(groupName);
	await notifications.push(notification, uids);

	logGroupEvent(caller, `group-${isSelf ? 'leave' : 'kick'}`, {
		groupName: groupName,
		targetUid: data.uid,
	});
};

groupsAPI.grant = async (caller, data) => {
	const groupName = await groups.getGroupNameByGroupSlug(data.slug);
	await isOwner(caller, groupName);

	await groups.ownership.grant(data.uid, groupName);
	logGroupEvent(caller, 'group-owner-grant', {
		groupName: groupName,
		targetUid: data.uid,
	});
};

groupsAPI.rescind = async (caller, data) => {
	const groupName = await groups.getGroupNameByGroupSlug(data.slug);
	await isOwner(caller, groupName);

	await groups.ownership.rescind(data.uid, groupName);
	logGroupEvent(caller, 'group-owner-rescind', {
		groupName: groupName,
		targetUid: data.uid,
	});
};

async function logGroupEvent(caller, eventName, details) {
	details.uid = caller.uid;
	await events.log(eventName, details);
}

async function isOwner(caller, groupName) {
	const isOwner = await groups.ownership.isOwner(caller.uid, groupName);
	if (!isOwner) {
		throw new Error('[[error:no-privileges]]');
	}
}
