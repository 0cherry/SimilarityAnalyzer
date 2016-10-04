class graph(object):
    def __init__(self, basic_blocks):
        self.root = node(basic_blocks[0])
        self.block_list = []
        for basic_block in basic_blocks:
            self.block_list.append( node(basic_block) )
        for basic_block in self.block_list:
            basic_block.setSuccs(self.block_list)
            basic_block.setPreds(self.block_list)
        self.blocks = len(self.block_list)
        self.edges = 0
        self.size = 0
        for block in self.block_list:
            self.edges += block.getCountOfInEdge()
            self.edges += block.getCountOfOutEdge()
            self.size += block.getBlockSize()

    def getGraphBlocks(self):
        return self.blocks

    def getGraphEdges(self):
        return self.edges

    def getGraphSize(self):
        return self.size


class node(object):
    def __init__(self, block_info):
        self.number = block_info['number']
        self.addr = block_info['addr']
        self.succsAddr = block_info['succs']
        self.predsAddr = block_info['preds']
        self.size = block_info['size']
        #self.mnemonics = block_info['mnemonics']
        self.succs = []
        self.preds = []


    def setSuccs(self, block_list):
        for basic_block in block_list:
            for succAddr in self.succsAddr:
                if succAddr == basic_block.addr:
                    self.succs.append(basic_block.number)
                    #self.succs.append(basic_block)


    def setPreds(self, block_list):
        for basic_block in block_list:
            for predAddr in self.predsAddr:
                if predAddr == basic_block.addr:
                    self.preds.append(basic_block.number)
                    #self.preds.append(basic_block)


    def getCountOfOutEdge(self):
        return len(self.succs)


    def getCountOfInEdge(self):
        return len(self.preds)


    def getBlockSize(self):
        return self.size


    def getDeleteCost(self):
        cost = self.getCountOfInEdge() + self.getCountOfOutEdge() + 1
        return cost


    def getMatchingCost(self, node):
        gapOutEdge = abs(self.getCountOfOutEdge() - node.getCountOfOutEdge())
        gapInEdge = abs(self.getCountOfInEdge() - node.getCountOfInEdge())
        gapSize = abs(self.getBlockSize() - node.getBlockSize())
        matchingCost = gapOutEdge + gapInEdge + gapSize
        return matchingCost


    def __str__(self):
        return 'number : {} addr : {} succsAddr : {} predsAddr : {} succsNode : {} predsNode : {}'.format(self.number, self.addr, self.succsAddr, self.predsAddr, self.succs, self.preds)
