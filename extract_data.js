const fs = require('fs');

const html = fs.readFileSync('dormant_btc.html', 'utf8');

// BitInfoCharts dormant addresses page has tables with id="tblOne" and "tblOne2"
const tables = [];
const tableIds = ['tblOne', 'tblOne2'];

tableIds.forEach(id => {
  const tableMatch = html.match(new RegExp(`<table[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/table>`));
  if (tableMatch) {
    tables.push(tableMatch[1]);
  }
});

const extractedData = [];

tables.forEach(tableContent => {
  // Split by <tr> but skip the header
  const trs = tableContent.split(/<tr[^>]*>/).slice(1);
  
  trs.forEach(tr => {
    // Address is inside an <a> tag
    const addrMatch = tr.match(/address\/([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})/);
    // Balance is in a <td> with data-val or just following the address
    // Looking for the first <td> after the address <td>
    // Actually, BitInfoCharts has data-val for the balance in the next <td>
    const balanceMatch = tr.match(/data-val="([\d,.]+)"[^>]*>([\d,.]+)\s*BTC/);
    
    if (addrMatch && balanceMatch) {
      extractedData.push({
        address: addrMatch[1],
        balance: balanceMatch[2] + ' BTC'
      });
    }
  });
});

if (extractedData.length > 0) {
  let md = "# Top Dormant Bitcoin Addresses (7+ Years)\n\n";
  md += "| Rank | Address | Balance |\n";
  md += "| :--- | :--- | :--- |\n";
  extractedData.slice(0, 100).forEach((item, index) => {
    md += `| ${index + 1} | ${item.address} | ${item.balance} |\n`;
  });
  fs.writeFileSync('dormant_addresses.md', md);
  console.log(`Successfully extracted ${Math.min(extractedData.length, 100)} addresses.`);
} else {
  console.error("No data extracted. The HTML structure might have changed.");
  // Debug: show a sample <tr>
  const firstTable = tables[0] || "";
  const firstTr = firstTable.match(/<tr[^>]*>[\s\S]*?<\/tr>/);
  if (firstTr) {
    console.log("Sample <tr> for debugging:", firstTr[0].slice(0, 500));
  }
}
