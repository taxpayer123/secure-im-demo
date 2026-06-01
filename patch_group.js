const fs = require('fs');
const p = 'src/pages/common/ChooseModal/index.tsx';
let c = fs.readFileSync(p, 'utf8');

// Remove the "only 1 person => single chat" block
const oldBlock = /\n\s*if (choosedList.length === 1) {\n\s*toSpecifiedConversation({\n\s*sourceID: choosedList[0].userID!,\n\s*sessionType: SessionType.Single,\n\s*});\n\s*break;\n\s*}\n\s*awiit IMSDK.createGroup({\n\s*groupInfo: {\n\s*groupType: GroupType.WorkingGroup,\n\s*groupName: groupBaseInfo.groupName,\n\s*faceURL: groupBaseInfo.groupAvatar,\n\s*},\n\s*memberUserIDs: choosedList.map((item) => item.userID!),\n\s*adminUserIDs: [],\n\s*});\n\s*break;/g;

const newBlock = `\n        console.log("[ChooseModal] Creating group:", {\n          groupName: groupBaseInfo.groupName,\n          memberCount: choosedList.length,\n          memberUserIDs: choosedList.map((item) => item.userID),\n        });\n        const { data: groupData } = await IMSDK.createGroup({\n          groupInfo: {\n            groupType: GroupType.WorkingGroup,\n            groupName: groupBaseInfo.groupName,\n            faceURL: groupBaseInfo.groupAvatar,\n          },\n          memberUserIDs: choosedList.map((item) => item.userID!),\n          adminUserIDs: [],\n        });\n        console.log("[ChooseModal] Group created:", groupData);\n        if (groupData?.groupID) {\n          await toSpecifiedConversation({\n            sourceID: groupData.groupID,\n            sessionType: SessionType.Group,\n          });\n        }\n        break;`;

if (c.match(oldBlock)) {
  c = c.replace(oldBlock, newBlock);
  fs.writeFileSync(p, c, 'utf8');
  console.log('Patched successfully!');
} else {
  console.log('OLD NOT FOUND, dumping...');
  const lines = c.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('createGroup')  || lines[i].includes('CRATE_GROUP')) {
      for (let j = Math.max(0, i - 5); j <= Math.min(lines.length - 1, i + 15); j++) {
        console.log((j+1) + ': ' + lines[j]);
      }
      break;
    }
  }
}