const fs=require('fs');
const c=fs.readFileSync('C:/Users/15074/Coze/secure-im-demo-new/src/pages/common/ChooseModal/index.tsx','utf8');
const lines=c.split(/\r\n|\n/);
for(let i=0;i<lines.length;i++){
  if(lines[i].includes('case "CRATE_GROUP"')){
    for(let j=i;j<Math.min(i+35,lines.length);j++){
      console.log((j+1)+': '+lines[j]);
    }
    break;
  }
}